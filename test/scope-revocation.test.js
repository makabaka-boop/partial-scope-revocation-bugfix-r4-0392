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

/** 走完整授权码流程拿到第一组令牌。 */
async function firstTokens(service, client = CLIENT_B, scopes = ['read:profile', 'write:docs']) {
  const verifier = generateCodeVerifier();
  const { code } = await service.issueAuthorizationCode({
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    codeChallenge: computeCodeChallenge(verifier, 'S256'),
    codeChallengeMethod: 'S256',
    scopes,
  });
  return service.exchangeAuthorizationCode({
    clientId: client.clientId,
    code,
    redirectUri: client.redirectUris[0],
    codeVerifier: verifier,
  });
}

/** 签发但暂不兑换的授权码。 */
async function issueCode(service, client = CLIENT_B, scopes = ['read:profile', 'write:docs']) {
  const verifier = generateCodeVerifier();
  const { code } = await service.issueAuthorizationCode({
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    codeChallenge: computeCodeChallenge(verifier, 'S256'),
    scopes,
  });
  return {
    code,
    verifier,
    exchange() {
      return service.exchangeAuthorizationCode({
        clientId: client.clientId,
        code,
        redirectUri: client.redirectUris[0],
        codeVerifier: verifier,
      });
    },
  };
}

const revoke = (service, clientId, scopes) =>
  service.setScopeGrant({ clientId, scopes, granted: false });
const regrant = (service, clientId, scopes) =>
  service.setScopeGrant({ clientId, scopes, granted: true });

test('部分撤销写权限：已签发的访问令牌立刻失去写范围，读范围保留', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  assert.deepEqual(t0.scope.sort(), ['read:profile', 'write:docs']);

  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);

  const info = await env.service.introspectAccessToken(t0.accessToken);
  assert.deepEqual(info.scope, ['read:profile']);
  env.close();
});

test('部分撤销后刷新轮换：新令牌只剩读范围，写范围不会被旧刷新令牌重新获得', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);

  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });

  // 轮换出的新访问/刷新凭据只带读范围
  assert.deepEqual(t1.scope, ['read:profile']);
  const info = await env.service.introspectAccessToken(t1.accessToken);
  assert.deepEqual(info.scope, ['read:profile']);

  // 旧访问令牌同样被收窄
  const oldInfo = await env.service.introspectAccessToken(t0.accessToken);
  assert.deepEqual(oldInfo.scope, ['read:profile']);

  // 再轮换一次，写范围依旧不会回来
  const t2 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t1.refreshToken,
  });
  assert.deepEqual(t2.scope, ['read:profile']);
  env.close();
});

test('撤销前签发的旧授权码：兑换时剔除写范围；全部范围被撤销的码拒绝签发', async () => {
  const env = await makeService();
  const pending = await issueCode(env.service);
  // 一张只含写范围、撤销前已签发的码
  const writeOnly = await issueCode(env.service, CLIENT_B, ['write:docs']);

  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  const tokens = await pending.exchange();
  assert.deepEqual(tokens.scope, ['read:profile']);

  // 只含写范围的码撤销后兑换必须被拒
  await assert.rejects(writeOnly.exchange(), (e) => e.error === 'invalid_scope');

  // 被拒兑换没有签发任何令牌，授权码已消费（旧码不可重放）
  const liveCodes = env.service.db
    .prepare('SELECT COUNT(*) c FROM auth_codes WHERE redeemed_at_ms IS NULL')
    .get().c;
  assert.equal(liveCodes, 0);
  env.close();
});

test('全部范围被撤销的兑换不签发令牌；即便之后重新授权，旧码也无法重放', async () => {
  const env = await makeService();
  const pending = await issueCode(env.service);
  await revoke(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);

  await assert.rejects(pending.exchange(), (e) => e.error === 'invalid_scope');

  const counts = env.service.db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM token_families)  AS families,
         (SELECT COUNT(*) FROM access_tokens)   AS accesses,
         (SELECT COUNT(*) FROM refresh_tokens)  AS refreshes`,
    )
    .get();
  assert.deepEqual(counts, { families: 0, accesses: 0, refreshes: 0 });

  // 重新授权后再用同一张旧码：码已消费，拒绝且仍不发令牌
  await regrant(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);
  await assert.rejects(pending.exchange(), (e) => e.error === 'invalid_grant');
  const counts2 = env.service.db
    .prepare('SELECT COUNT(*) c FROM token_families')
    .get().c;
  assert.equal(counts2, 0);
  env.close();
});

test('撤销后重新授权：旧凭据（码/令牌家族）不能恢复写范围，只有之后签发的凭据带写范围', async () => {
  const env = await makeService();
  const oldCode = await issueCode(env.service);
  const t0 = await firstTokens(env.service);

  // 撤销 -> 旧码收窄、旧家族收窄
  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  const narrowed = await oldCode.exchange();
  assert.deepEqual(narrowed.scope, ['read:profile']);
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);

  // 重新授权写范围
  await regrant(env.service, CLIENT_B.clientId, ['write:docs']);

  // 旧家族继续轮换：写范围不复活（纪元已推进，快照版本对不上）
  const t2 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t1.refreshToken,
  });
  assert.deepEqual(t2.scope, ['read:profile']);
  const oldAccess = await env.service.introspectAccessToken(t0.accessToken);
  assert.deepEqual(oldAccess.scope, ['read:profile']);

  // 撤销前签发、尚未兑换的码也不能借重新授权拿回写范围
  const pendingSinceBefore = await issueCode(env.service);
  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  await regrant(env.service, CLIENT_B.clientId, ['write:docs']);
  const replayed = await pendingSinceBefore.exchange();
  assert.deepEqual(replayed.scope, ['read:profile']);

  // 撤销时已被拒绝的全撤销码，重新授权后依旧不能兑换
  const dead = await issueCode(env.service);
  await revoke(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);
  await assert.rejects(dead.exchange(), () => true);
  await regrant(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);
  await assert.rejects(dead.exchange(), (e) => e.error === 'invalid_grant');

  // 重新授权之后新签发的授权码与令牌才重新带上写范围
  const fresh = await firstTokens(env.service);
  assert.deepEqual(fresh.scope.sort(), ['read:profile', 'write:docs']);
  const freshInfo = await env.service.introspectAccessToken(fresh.accessToken);
  assert.deepEqual(freshInfo.scope.sort(), ['read:profile', 'write:docs']);
  env.close();
});

test('撤销只作用于指定客户端：另一客户端的同名范围与凭据不受连带影响', async () => {
  const env = await makeService();
  // A 的 open scopes 为 read:profile/read:docs，与 B 的 write:docs 不同名；
  // 两客户端都有 read:profile，用它验证按客户端隔离
  const aTokens = await firstTokens(env.service, CLIENT_A, ['read:profile']);
  const bTokens = await firstTokens(env.service, CLIENT_B);

  await revoke(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);

  // A 的 read:profile 令牌照常有效，范围不减
  const aInfo = await env.service.introspectAccessToken(aTokens.accessToken);
  assert.deepEqual(aInfo.scope, ['read:profile']);
  const aRefresh = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: aTokens.refreshToken,
  });
  assert.deepEqual(aRefresh.scope, ['read:profile']);

  // B 已全撤销：访问被拒、刷新被拒，且不产生新令牌
  await assert.rejects(
    env.service.introspectAccessToken(bTokens.accessToken),
    (e) => e.error === 'invalid_token',
  );
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: bTokens.refreshToken,
    }),
    (e) => e.error === 'invalid_scope',
  );

  // 对 A 撤销/再授权 read:profile 不改变 B 该范围的撤销态
  await revoke(env.service, CLIENT_A.clientId, ['read:profile']);
  await regrant(env.service, CLIENT_A.clientId, ['read:profile']);
  await assert.rejects(
    env.service.introspectAccessToken(bTokens.accessToken),
    (e) => e.error === 'invalid_token',
  );

  // B 重新授权后，旧家族仍然只剩（实际为零）撤销前快照的有效范围 => 依旧失效；
  // A 之后新签发的码不受 B 影响
  await regrant(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: bTokens.refreshToken,
    }),
    (e) => e.error === 'invalid_scope',
  );
  const aFresh = await firstTokens(env.service, CLIENT_A, ['read:profile']);
  assert.deepEqual(aFresh.scope, ['read:profile']);
  env.close();
});

test('全部范围撤销后刷新在消费刷新令牌之前拒绝：不轮换、不留多余令牌', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  await revoke(env.service, CLIENT_B.clientId, ['read:profile', 'write:docs']);

  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_scope',
  );

  // 刷新令牌没有被消费（仍未轮换），库里也没有新增令牌
  const rt = env.service.db
    .prepare('SELECT consumed_at_ms FROM refresh_tokens WHERE family_id = ?')
    .get(t0.familyId);
  assert.equal(rt.consumed_at_ms, null);
  const counts = env.service.db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM access_tokens)  AS accesses,
         (SELECT COUNT(*) FROM refresh_tokens) AS refreshes,
         (SELECT COUNT(*) FROM token_families) AS families`,
    )
    .get();
  assert.deepEqual(counts, { accesses: 1, refreshes: 1, families: 1 });
  env.close();
});

test('部分撤销与到期正交：范围收窄结果在访问/刷新令牌到期时仍一致', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);

  env.clock.tick(60 * 60 * 1000 + 1); // 访问令牌到期
  await assert.rejects(
    env.service.introspectAccessToken(t0.accessToken),
    (e) => e.error === 'invalid_token' && /过期/.test(e.message),
  );

  // 刷新令牌未过期，仍可轮换出只读新令牌
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);

  // 推进到刷新令牌到期：拒绝，且写范围始终没回来
  env.clock.tick(30 * 24 * 60 * 60 * 1000);
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t1.refreshToken,
    }),
    (e) => e.error === 'invalid_grant' && /过期/.test(e.message),
  );
  env.close();
});

test('部分撤销与家族重放撤销正交：已用刷新令牌重放仍撤销整家族，结果与无撤销时一致', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);

  // 读范围还在，正常轮换一次
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);

  // 重放 t0：家族撤销（包括最新 t1 的只读令牌）
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_grant' && /重放/.test(e.message),
  );

  const family = env.service.db
    .prepare('SELECT revoked_at_ms, revoke_reason FROM token_families WHERE id = ?')
    .get(t0.familyId);
  assert.ok(family.revoked_at_ms !== null);
  assert.equal(family.revoke_reason, 'reused_refresh_token');

  // 家族撤销优先：最新只读访问令牌也立即失效
  await assert.rejects(
    env.service.introspectAccessToken(t1.accessToken),
    (e) => e.error === 'invalid_token' && /家族撤销/.test(e.message),
  );

  // 即便重新授权写范围，家族仍处于撤销态
  await regrant(env.service, CLIENT_B.clientId, ['write:docs']);
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t1.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );
  env.close();
});

test('撤销/重新授权状态持久化：重启后范围收窄、纪元版本与拒绝结果完全一致', async () => {
  const env = await makeService();
  // 保留原始兑换参数，重启后用新实例兑换（授权码本就不依赖实例内存状态）
  const pending = await issueCode(env.service);
  const pendingExchange = {
    clientId: CLIENT_B.clientId,
    code: pending.code,
    redirectUri: CLIENT_B.redirectUris[0],
    codeVerifier: pending.verifier,
  };
  const t0 = await firstTokens(env.service);

  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope, ['read:profile']);
  env.close();

  const clock2 = new FakeClock(env.clock.now() + 60_000);
  const restarted = openAnotherService(env.dbPath, clock2);

  // 重启后旧访问令牌仍然只读
  const info = await restarted.introspectAccessToken(t0.accessToken);
  assert.deepEqual(info.scope, ['read:profile']);
  const info1 = await restarted.introspectAccessToken(t1.accessToken);
  assert.deepEqual(info1.scope, ['read:profile']);

  // 撤销前签发的旧码重启后兑换仍被收窄
  const tokensFromOldCode = await restarted.exchangeAuthorizationCode(pendingExchange);
  assert.deepEqual(tokensFromOldCode.scope, ['read:profile']);

  // 重启后重新授权：旧家族仍不能恢复写范围
  await regrant(restarted, CLIENT_B.clientId, ['write:docs']);
  const t2 = await restarted.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: t1.refreshToken,
  });
  assert.deepEqual(t2.scope, ['read:profile']);

  // 之后新签发的凭据才带写范围
  const fresh = await firstTokens(restarted);
  assert.deepEqual(fresh.scope.sort(), ['read:profile', 'write:docs']);

  // 另一客户端重启后不受影响
  const aInfo = await restarted.introspectAccessToken(
    (await firstTokens(restarted, CLIENT_A, ['read:profile'])).accessToken,
  );
  assert.deepEqual(aInfo.scope, ['read:profile']);
  restarted.close();
});

test('重复撤销/重复授权幂等：纪元只在状态翻转时推进', async () => {
  const env = await makeService();
  const versionOf = async () =>
    (
      await env.service.db.get(
        'SELECT grant_version FROM scope_grants WHERE client_id=? AND scope=?',
        [CLIENT_B.clientId, 'write:docs'],
      )
    ).grant_version;

  const result1 = await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  assert.deepEqual(result1.changed, ['write:docs']);
  const v1 = await versionOf();

  const result2 = await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  assert.deepEqual(result2.changed, []);
  assert.equal(await versionOf(), v1, '重复撤销不推进纪元');

  const result3 = await regrant(env.service, CLIENT_B.clientId, ['write:docs']);
  assert.deepEqual(result3.changed, ['write:docs']);
  assert.equal(await versionOf(), v1 + 1, '重新授权推进纪元');

  const result4 = await regrant(env.service, CLIENT_B.clientId, ['write:docs']);
  assert.deepEqual(result4.changed, []);
  env.close();
});

test('撤销期间不能签发含被撤销范围的新授权码；重新授权后才可签发', async () => {
  const env = await makeService();
  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);

  await assert.rejects(
    issueCode(env.service, CLIENT_B, ['read:profile', 'write:docs']),
    (e) => e.error === 'invalid_scope',
  );
  // 只申请读范围仍可签发
  const readOnly = await issueCode(env.service, CLIENT_B, ['read:profile']);
  const tokens = await readOnly.exchange();
  assert.deepEqual(tokens.scope, ['read:profile']);

  await regrant(env.service, CLIENT_B.clientId, ['write:docs']);
  const both = await firstTokens(env.service);
  assert.deepEqual(both.scope.sort(), ['read:profile', 'write:docs']);
  env.close();
});

test('升级前已存在的旧数据库：回填默认授权 v1，旧令牌范围原样保留且之后可正常撤销', async () => {
  // 用“旧 schema”（无 scope_grants / 快照表）建库并写入客户端与一组旧令牌
  const { Db } = require('../src/db');
  const { hashToken } = require('../src/crypto');
  const { tempDbPath } = require('./helpers');
  const oldDbPath = tempDbPath();
  const oldAccess = 'old-access-raw-token';
  const oldRefresh = 'old-refresh-raw-token';
  const oldDb = new Db(oldDbPath);
  oldDb.exec(`
    CREATE TABLE clients (client_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at_ms INTEGER NOT NULL);
    CREATE TABLE client_redirect_uris (client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, PRIMARY KEY (client_id, redirect_uri));
    CREATE TABLE client_scopes (client_id TEXT NOT NULL, scope TEXT NOT NULL, PRIMARY KEY (client_id, scope));
    CREATE TABLE auth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
      code_challenge TEXT NOT NULL, code_challenge_method TEXT NOT NULL, scope TEXT NOT NULL,
      expires_at_ms INTEGER NOT NULL, redeemed_at_ms INTEGER, created_at_ms INTEGER NOT NULL);
    CREATE TABLE token_families (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL, scope TEXT NOT NULL,
      revoked_at_ms INTEGER, revoke_reason TEXT, created_at_ms INTEGER NOT NULL);
    CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, family_id INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
      consumed_at_ms INTEGER, superseded_by_family_token_hash TEXT, created_at_ms INTEGER NOT NULL);
    CREATE TABLE access_tokens (token_hash TEXT PRIMARY KEY, family_id INTEGER NOT NULL, scope TEXT NOT NULL,
      expires_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL);
    INSERT INTO clients VALUES ('client-b', '客户端 B', 0);
    INSERT INTO client_redirect_uris VALUES ('client-b', 'http://client-b.example/cb');
    INSERT INTO client_scopes VALUES ('client-b', 'read:profile'), ('client-b', 'write:docs');
    INSERT INTO token_families (id, client_id, scope, created_at_ms) VALUES (1, 'client-b', 'read:profile write:docs', 0);
    INSERT INTO access_tokens VALUES ('${hashToken(oldAccess)}', 1, 'read:profile write:docs', 9999999999999, 0);
    INSERT INTO refresh_tokens VALUES ('${hashToken(oldRefresh)}', 1, 9999999999999, NULL, NULL, 0);
  `);
  oldDb.close();

  // 用新代码打开同一文件 => migrate 自动建表并幂等回填
  const env = await makeService({ dbPath: oldDbPath });

  const grants = await env.service.db.all(
    'SELECT scope, granted, grant_version FROM scope_grants WHERE client_id = ? ORDER BY scope',
    [CLIENT_B.clientId],
  );
  assert.deepEqual(grants, [
    { scope: 'read:profile', granted: 1, grant_version: 1 },
    { scope: 'write:docs', granted: 1, grant_version: 1 },
  ]);

  // 回填后旧令牌两个范围都保留
  const before = await env.service.introspectAccessToken(oldAccess);
  assert.deepEqual(before.scope.sort(), ['read:profile', 'write:docs']);

  // 回填的旧家族同样受新的部分撤销约束（立即收窄）
  await revoke(env.service, CLIENT_B.clientId, ['write:docs']);
  const after = await env.service.introspectAccessToken(oldAccess);
  assert.deepEqual(after.scope, ['read:profile']);
  const rotated = await env.service.refreshAccessToken({
    clientId: CLIENT_B.clientId,
    refreshToken: oldRefresh,
  });
  assert.deepEqual(rotated.scope, ['read:profile']);
  env.close();
});

test('撤销未知客户端/未开放范围被拒，不产生任何授权状态写入', async () => {
  const env = await makeService();
  const countGrants = () =>
    env.service.db.prepare('SELECT COUNT(*) c FROM scope_grants').get().c;
  const before = countGrants();
  // 注册时为 A 两个、B 两个开放范围各写一行默认授权
  assert.equal(before, 4);

  await assert.rejects(
    env.service.setScopeGrant({ clientId: 'no-such-client', scopes: ['read:profile'], granted: false }),
    (e) => e.error === 'invalid_client',
  );
  await assert.rejects(
    revoke(env.service, CLIENT_A.clientId, ['write:docs']),
    (e) => e.error === 'invalid_scope',
  );
  await assert.rejects(
    env.service.setScopeGrant({ clientId: CLIENT_B.clientId, scopes: ['write:docs'], granted: 'yes' }),
    (e) => e.error === 'invalid_request',
  );
  assert.equal(countGrants(), before, '失败请求不写入授权状态');
  // 所有范围仍处于默认授权态
  const revoked = env.service.db
    .prepare('SELECT COUNT(*) c FROM scope_grants WHERE granted = 0')
    .get().c;
  assert.equal(revoked, 0);
  env.close();
});
