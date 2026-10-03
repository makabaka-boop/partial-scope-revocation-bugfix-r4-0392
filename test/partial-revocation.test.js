'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  makeService,
  openAnotherService,
  CLIENT_A,
  CLIENT_B,
} = require('./helpers');
const { FakeClock } = require('../src/clock');
const {
  generateCodeVerifier,
  computeCodeChallenge,
} = require('../src/crypto');

/** “用户确认范围 -> 签发授权码”，返回码与兑换所需参数。 */
async function issue(service, client, scopes) {
  const verifier = generateCodeVerifier();
  const challenge = computeCodeChallenge(verifier, 'S256');
  const { code } = await service.issueAuthorizationCode({
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    scopes,
  });
  return {
    verifier,
    exchange(svc = service) {
      return svc.exchangeAuthorizationCode({
        clientId: client.clientId,
        code,
        redirectUri: client.redirectUris[0],
        codeVerifier: verifier,
      });
    },
  };
}

async function firstTokens(service, client, scopes) {
  const granted = await issue(service, client, scopes);
  return granted.exchange();
}

function countRows(service, table) {
  return service.db.prepare(`SELECT COUNT(*) c FROM ${table}`).get().c;
}

test('部分撤销：旧授权码兑换后只保留未撤销范围，写权限不能由旧码获得', async () => {
  const env = await makeService();
  // B 同时拥有读/写范围，撤销前签发一张读+写的授权码（尚未兑换）
  const old = await issue(
    env.service,
    CLIENT_B,
    ['read:profile', 'write:docs'],
  );

  // 用户只撤销 B 的写权限，读保留
  const res = await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });
  assert.deepEqual(res, { clientId: CLIENT_B.clientId, scope: ['write:docs'], granted: false });

  // 撤销前的旧码仍可兑换（一次性消费语义不变），但令牌上只剩读范围
  const tokens = await old.exchange();
  assert.deepEqual(tokens.scope, ['read:profile']);

  // 资源访问：旧码换来的访问令牌不能执行写操作
  const info = await env.service.introspectAccessToken(tokens.accessToken);
  assert.deepEqual(info.scope, ['read:profile']);

  // 刷新轮换出的新令牌同样不能拿回写范围
  const rotated = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: tokens.refreshToken,
  });
  assert.deepEqual(rotated.scope, ['read:profile']);
  const info2 = await env.service.introspectAccessToken(rotated.accessToken);
  assert.deepEqual(info2.scope, ['read:profile']);

  // 部分撤销不触动家族撤销状态：家族仍可正常轮换
  const family = env.service.db
    .prepare('SELECT revoked_at_ms FROM token_families WHERE id=?')
    .get(tokens.familyId);
  assert.equal(family.revoked_at_ms, null);
  env.close();
});

test('部分撤销：撤销前已签发的访问令牌立即失去被撤销范围，保留范围继续有效', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);
  assert.deepEqual((await env.service.introspectAccessToken(t0.accessToken)).scope.sort(),
    ['read:profile', 'write:docs']);

  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });

  // 已有访问令牌：写范围立即消失，读范围仍在，令牌本身不失效
  const info = await env.service.introspectAccessToken(t0.accessToken);
  assert.deepEqual(info.scope, ['read:profile']);

  // 旧刷新令牌轮换：新令牌对同样只剩读范围
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);
  env.close();
});

test('重新授权：撤销前的旧授权码/旧令牌家族不能恢复写范围，只有之后签发的凭据获得', async () => {
  const env = await makeService();
  // 撤销前：一张未兑换的旧码 + 一个已兑换的旧家族，均含写范围
  const oldCode = await issue(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);
  const oldTokens = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);

  // 撤销写 -> 再重新授权写
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: true,
  });

  // 撤销前的旧授权码：重新授权后仍不能借旧世代恢复写范围
  const fromOldCode = await oldCode.exchange();
  assert.deepEqual(fromOldCode.scope, ['read:profile']);
  // 它刷新也拿不到写
  assert.deepEqual(
    (
      await env.service.refreshAccessToken({
        clientId: CLIENT_B.clientId,
        refreshToken: fromOldCode.refreshToken,
      })
    ).scope,
    ['read:profile'],
  );

  // 撤销前的旧令牌家族：轮换链上始终只有读范围
  const oldRotated = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: oldTokens.refreshToken,
  });
  assert.deepEqual(oldRotated.scope, ['read:profile']);

  // 重新授权之后签发的新授权码：完整读+写，兑换/刷新/资源访问全链路写范围有效
  const newTokens = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);
  assert.deepEqual(newTokens.scope.sort(), ['read:profile', 'write:docs']);
  const info = await env.service.introspectAccessToken(newTokens.accessToken);
  assert.deepEqual(info.scope.sort(), ['read:profile', 'write:docs']);
  const newRotated = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: newTokens.refreshToken,
  });
  assert.deepEqual(newRotated.scope.sort(), ['read:profile', 'write:docs']);
  env.close();
});

test('撤销按客户端隔离：A 的范围撤销不连带影响 B 的凭据', async () => {
  const env = await makeService();
  // 两客户端共享 read:profile；各自另有一个范围
  const tA = await firstTokens(env.service, CLIENT_A, [
    'read:profile',
    'read:docs',
  ]);
  const tB = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);

  await env.service.setScopeGrant({
    clientId: CLIENT_A.clientId,
    scopes: ['read:profile'],
    granted: false,
  });

  // A 的令牌失去 read:profile（只剩 read:docs）
  assert.deepEqual(
    (await env.service.introspectAccessToken(tA.accessToken)).scope,
    ['read:docs'],
  );
  // B 完全不受连带影响：两个范围（含共享的 read:profile）原样有效
  assert.deepEqual(
    (await env.service.introspectAccessToken(tB.accessToken)).scope.sort(),
    ['read:profile', 'write:docs'],
  );
  // B 的轮换照常携带全部范围
  const rB = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: tB.refreshToken,
  });
  assert.deepEqual(rB.scope.sort(), ['read:profile', 'write:docs']);

  // 对 A 重新授权 read:profile 也不影响 B
  await env.service.setScopeGrant({
    clientId: CLIENT_A.clientId,
    scopes: ['read:profile'],
    granted: true,
  });
  assert.deepEqual(
    (await env.service.introspectAccessToken(tB.accessToken)).scope.sort(),
    ['read:profile', 'write:docs'],
  );
  env.close();
});

test('全部范围被撤销：旧码兑换被拒、不签发任何令牌，且一次性码被消费不复活', async () => {
  const env = await makeService();
  const old = await issue(env.service, CLIENT_A, ['read:profile', 'read:docs']);

  await env.service.setScopeGrant({
    clientId: CLIENT_A.clientId,
    scopes: ['read:profile', 'read:docs'],
    granted: false,
  });

  assert.equal(countRows(env.service, 'token_families'), 0);
  assert.equal(countRows(env.service, 'access_tokens'), 0);
  assert.equal(countRows(env.service, 'refresh_tokens'), 0);

  await assert.rejects(old.exchange(), (e) =>
    e.error === 'invalid_scope' && /全部撤销/.test(e.message));

  // 拒绝不留下多余令牌
  assert.equal(countRows(env.service, 'token_families'), 0);
  assert.equal(countRows(env.service, 'access_tokens'), 0);
  assert.equal(countRows(env.service, 'refresh_tokens'), 0);

  // 授权码已被消费（commitAfterThrow），重放给 invalid_grant 而不是二次发令牌
  await assert.rejects(old.exchange(), (e) => e.error === 'invalid_grant');
  assert.equal(countRows(env.service, 'token_families'), 0);
  env.close();
});

test('全部范围被撤销：旧家族刷新被 invalid_scope 拒绝，不消费刷新令牌也不写新令牌', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service, CLIENT_A, [
    'read:profile',
    'read:docs',
  ]);

  await env.service.setScopeGrant({
    clientId: CLIENT_A.clientId,
    scopes: ['read:profile', 'read:docs'],
    granted: false,
  });

  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_scope' && /全部撤销/.test(e.message),
  );

  // 没有新令牌
  assert.equal(countRows(env.service, 'token_families'), 1);
  assert.equal(countRows(env.service, 'access_tokens'), 1);
  assert.equal(countRows(env.service, 'refresh_tokens'), 1);
  // 刷新令牌未被消费（与原“范围校验失败不消费令牌”的语义一致）
  const rt = env.service.db
    .prepare('SELECT consumed_at_ms FROM refresh_tokens')
    .get();
  assert.equal(rt.consumed_at_ms, null);

  // 访问令牌因全部范围失效而不可用
  await assert.rejects(
    env.service.introspectAccessToken(t0.accessToken),
    (e) => e.error === 'invalid_token',
  );

  // 即使之后重新授权，旧家族依旧不能拿回任何范围（旧世代永久失效）
  await env.service.setScopeGrant({
    clientId: CLIENT_A.clientId,
    scopes: ['read:profile', 'read:docs'],
    granted: true,
  });
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_scope',
  );
  assert.equal(countRows(env.service, 'refresh_tokens'), 1);
  env.close();
});

test('部分撤销后重放已用刷新令牌：家族撤销结果与原有逻辑一致（含最新令牌立即失效）', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);

  // 撤销写范围后正常轮换一次，t1 只带读范围
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);

  // 重放最老的 t0 => 整个家族撤销
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_grant' && /重放/.test(e.message),
  );

  const family = env.service.db
    .prepare('SELECT revoked_at_ms, revoke_reason FROM token_families WHERE id=?')
    .get(t0.familyId);
  assert.ok(family.revoked_at_ms !== null);
  assert.equal(family.revoke_reason, 'reused_refresh_token');

  // 最新的 t1 刷新/访问令牌立即失效——与无部分撤销时的家族撤销结果完全一致
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t1.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );
  await assert.rejects(
    env.service.introspectAccessToken(t1.accessToken),
    (e) => e.error === 'invalid_token',
  );
  env.close();
});

test('部分撤销与到期：访问/刷新令牌到期行为不变，未到期刷新只取剩余范围', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });

  // 访问令牌到期：优先报过期（原有结果不变）
  env.clock.tick(60 * 60 * 1000 + 1);
  await assert.rejects(
    env.service.introspectAccessToken(t0.accessToken),
    (e) => e.error === 'invalid_token' && /过期/.test(e.message),
  );

  // 刷新令牌未到期：仍可轮换，范围为剩余的读
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);

  // 刷新令牌到期：原有 invalid_grant 行为不变
  env.clock.tick(30 * 24 * 60 * 60 * 1000);
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t1.refreshToken,
    }),
    (e) => e.error === 'invalid_grant' && /刷新令牌已过期/.test(e.message),
  );
  env.close();
});

test('服务重启：部分撤销与重新授权的世代状态持久，范围结果与重启前一致', async () => {
  const env = await makeService();
  // 旧家族（撤销前）与旧码
  const oldCode = await issue(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);
  const t0 = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);

  // 撤销写后轮换出 t1；再重新授权写
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: true,
  });
  // 重新授权后签发的新家族
  const tNew = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);

  env.close();

  const clock2 = new FakeClock(env.clock.now() + 60_000);
  const restarted = openAnotherService(env.dbPath, clock2);

  // 旧码重启后仍只剩读范围
  assert.deepEqual((await oldCode.exchange(restarted)).scope, ['read:profile']);
  // 旧家族的最新刷新令牌（t1）重启后仍不能恢复写
  const rotated = await restarted.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t1.refreshToken,
  });
  assert.deepEqual(rotated.scope, ['read:profile']);
  assert.deepEqual(
    (await restarted.introspectAccessToken(tNew.accessToken)).scope.sort(),
    ['read:profile', 'write:docs'],
  );
  // 重放 t0：重启后家族撤销结果依旧（重放即撤销）
  await assert.rejects(
    restarted.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );
  await assert.rejects(
    restarted.introspectAccessToken(rotated.accessToken),
    (e) => e.error === 'invalid_token',
  );
  restarted.close();
});

test('撤销/授权接口校验：未知客户端、未开放范围、granted 类型均被拒', async () => {
  const env = await makeService();

  await assert.rejects(
    env.service.setScopeGrant({
      clientId: 'unknown',
      scopes: ['read:profile'],
      granted: false,
    }),
    (e) => e.error === 'invalid_client',
  );
  await assert.rejects(
    env.service.setScopeGrant({
      clientId: CLIENT_A.clientId,
      scopes: ['write:docs'], // 未对 A 开放
      granted: false,
    }),
    (e) => e.error === 'invalid_scope',
  );
  await assert.rejects(
    env.service.setScopeGrant({
      clientId: CLIENT_A.clientId,
      scopes: ['read:profile'],
      granted: 'yes',
    }),
    (e) => e.error === 'invalid_request',
  );
  env.close();
});

test('撤销/授权幂等：重复操作世代不叠加，凭据有效性结果一致', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service, CLIENT_B, [
    'read:profile',
    'write:docs',
  ]);

  const revoke = () =>
    env.service.setScopeGrant({
      clientId: CLIENT_B.clientId,
      scopes: ['write:docs'],
      granted: false,
    });
  const grant = () =>
    env.service.setScopeGrant({
      clientId: CLIENT_B.clientId,
      scopes: ['write:docs'],
      granted: true,
    });

  await revoke();
  await revoke(); // 幂等：gen 停在 1
  // 请求与家族原始范围完全一致（允许），但实际只签发剩余范围
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
    scopes: ['read:profile', 'write:docs'],
  });
  assert.deepEqual(t1.scope, ['read:profile']);

  await grant();
  await grant(); // 幂等：gen 停在 2
  // 旧家族仍不能恢复写
  const t2 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t1.refreshToken,
  });
  assert.deepEqual(t2.scope, ['read:profile']);

  // 刷新时借“只传读范围”缩小请求仍然非法（必须与家族原始范围完全一致）
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t2.refreshToken,
      scopes: ['read:profile'],
    }),
    (e) => e.error === 'invalid_scope',
  );
  env.close();
});

test('撤销期间新签发请求被拒：已撤销范围不能出现在新授权码上', async () => {
  const env = await makeService();
  await env.service.setScopeGrant({
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });
  await assert.rejects(
    issue(env.service, CLIENT_B, ['read:profile', 'write:docs']),
    (e) => e.error === 'invalid_scope' && /write:docs/.test(e.message),
  );
  // 不含被撤销范围的请求正常
  const tokens = await firstTokens(env.service, CLIENT_B, ['read:profile']);
  assert.deepEqual(tokens.scope, ['read:profile']);
  assert.equal(countRows(env.service, 'auth_codes'), 1);
  env.close();
});

// ---------- HTTP 全链路：/scope-grant -> /token(authorization_code/refresh) -> /introspect ----------

async function startHttp(service) {
  const { createJsonServer } = require('../src/http');
  const server = createJsonServer(service);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  return {
    baseUrl,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function post(baseUrl, path, body) {
  const res = await fetch(baseUrl + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  return { status: res.status, json };
}

test('HTTP 全链路：撤销写 -> 旧码/刷新/资源访问均无写；重新授权 -> 仅之后凭据有写', async () => {
  const env = await makeService();
  const http = await startHttp(env.service);

  // 撤销前签发读+写授权码（不兑换）
  const verifier = generateCodeVerifier();
  const issued = await post(http.baseUrl, '/authorize', {
    clientId: CLIENT_B.clientId,
    redirectUri: CLIENT_B.redirectUris[0],
    codeChallenge: computeCodeChallenge(verifier, 'S256'),
    codeChallengeMethod: 'S256',
    scopes: ['read:profile', 'write:docs'],
  });
  assert.equal(issued.status, 200);

  // 撤销写
  const revoked = await post(http.baseUrl, '/scope-grant', {
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: false,
  });
  assert.equal(revoked.status, 200);
  assert.equal(revoked.json.granted, false);

  // 旧码兑换：只有读
  const exchanged = await post(http.baseUrl, '/token', {
    grantType: 'authorization_code',
    clientId: CLIENT_B.clientId,
    code: issued.json.code,
    redirectUri: CLIENT_B.redirectUris[0],
    codeVerifier: verifier,
  });
  assert.equal(exchanged.status, 200);
  assert.deepEqual(exchanged.json.scope, ['read:profile']);

  // 资源访问：无写
  const introspected = await post(http.baseUrl, '/introspect', {
    accessToken: exchanged.json.accessToken,
  });
  assert.deepEqual(introspected.json.scope, ['read:profile']);

  // 刷新轮换：仍无写
  const rotated = await post(http.baseUrl, '/token', {
    grantType: 'refresh_token',
    clientId: CLIENT_B.clientId,
    refreshToken: exchanged.json.refreshToken,
  });
  assert.equal(rotated.status, 200);
  assert.deepEqual(rotated.json.scope, ['read:profile']);

  // 重新授权
  await post(http.baseUrl, '/scope-grant', {
    clientId: CLIENT_B.clientId,
    scopes: ['write:docs'],
    granted: true,
  });

  // 旧家族再刷新仍无写
  const rotated2 = await post(http.baseUrl, '/token', {
    grantType: 'refresh_token',
    clientId: CLIENT_B.clientId,
    refreshToken: rotated.json.refreshToken,
  });
  assert.deepEqual(rotated2.json.scope, ['read:profile']);

  // 之后签发的新码：读+写完整
  const v2 = generateCodeVerifier();
  const issued2 = await post(http.baseUrl, '/authorize', {
    clientId: CLIENT_B.clientId,
    redirectUri: CLIENT_B.redirectUris[0],
    codeChallenge: computeCodeChallenge(v2, 'S256'),
    scopes: ['read:profile', 'write:docs'],
  });
  const exchanged2 = await post(http.baseUrl, '/token', {
    grantType: 'authorization_code',
    clientId: CLIENT_B.clientId,
    code: issued2.json.code,
    redirectUri: CLIENT_B.redirectUris[0],
    codeVerifier: v2,
  });
  assert.deepEqual(exchanged2.json.scope.sort(), ['read:profile', 'write:docs']);

  await http.close();
  env.close();
});
