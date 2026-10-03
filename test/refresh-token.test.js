'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  makeService,
  openAnotherService,
  tempDbPath,
  CLIENT_A,
  CLIENT_B,
  Gate,
  settle,
} = require('./helpers');
const { FakeClock } = require('../src/clock');
const {
  generateCodeVerifier,
  computeCodeChallenge,
} = require('../src/crypto');

/** 走完整授权码流程拿到第一组令牌。 */
async function firstTokens(service, client = CLIENT_A, scopes = ['read:profile']) {
  const verifier = generateCodeVerifier();
  const challenge = computeCodeChallenge(verifier, 'S256');
  const { code } = await service.issueAuthorizationCode({
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    codeChallenge: challenge,
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

test('刷新令牌每次使用都轮换：旧令牌失效，新令牌可用，轮换链持续', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);

  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.notEqual(t1.refreshToken, t0.refreshToken);
  assert.notEqual(t1.accessToken, t0.accessToken);
  assert.equal(t1.familyId, t0.familyId); // 同一家族

  // 新刷新令牌继续可用，形成轮换链
  const t2 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t1.refreshToken,
  });
  assert.notEqual(t2.refreshToken, t1.refreshToken);
  assert.notEqual(t2.refreshToken, t0.refreshToken);
  assert.equal(t2.familyId, t0.familyId);

  // 链条末端令牌可用
  const info = await env.service.introspectAccessToken(t2.accessToken);
  assert.equal(info.clientId, CLIENT_A.clientId);

  // 链上每个旧令牌都已失效（重放后果——家族撤销——由下一个测试专门断言）
  for (const old of [t0.refreshToken, t1.refreshToken]) {
    await assert.rejects(
      env.service.refreshAccessToken({
        clientId: CLIENT_A.clientId,
        refreshToken: old,
      }),
      (e) => e.error === 'invalid_grant',
    );
  }
  env.close();
});

test('重放旧刷新令牌 => 整个家族被撤销，包括已轮换出的最新令牌', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t0.refreshToken,
  });
  const t2 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t1.refreshToken,
  });

  // 攻击者重放最老的 t0
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );

  // 家族标记撤销、撤销原因记录在案
  const family = env.service.db
    .prepare('SELECT revoked_at_ms, revoke_reason FROM token_families WHERE id=?')
    .get(t0.familyId);
  assert.ok(family.revoked_at_ms !== null);
  assert.equal(family.revoke_reason, 'reused_refresh_token');

  // 最新的刷新令牌 t2 已失效
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t2.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );

  // 家族内所有访问令牌（含最新的 t2.accessToken）立即失效
  await assert.rejects(
    env.service.introspectAccessToken(t2.accessToken),
    (e) => e.error === 'invalid_token',
  );
  // 早期访问令牌同样失效
  await assert.rejects(
    env.service.introspectAccessToken(t1.accessToken),
    (e) => e.error === 'invalid_token',
  );
  env.close();
});

test('并发刷新同一刷新令牌：恰好一个成功；另一个的重放导致整个家族被撤销', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);

  // 单实例内两个并发请求使用同一刷新令牌（互斥锁串行化 + 条件 UPDATE）
  const [r1, r2] = await Promise.all([
    settle(
      env.service.refreshAccessToken({
        clientId: CLIENT_A.clientId,
        refreshToken: t0.refreshToken,
      }),
    ),
    settle(
      env.service.refreshAccessToken({
        clientId: CLIENT_A.clientId,
        refreshToken: t0.refreshToken,
      }),
    ),
  ]);

  const success = r1.ok ? r1 : r2;
  const failure = r1.ok ? r2 : r1;
  assert.equal(r1.ok !== r2.ok, true, '必须恰有一个成功');
  assert.equal(failure.error.error, 'invalid_grant');
  assert.match(failure.error.message, /重放/);

  // 家族已撤销 => 获胜者拿到的“最新”刷新令牌也必须立即不可再用
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: success.value.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );
  await assert.rejects(
    env.service.introspectAccessToken(success.value.accessToken),
    (e) => e.error === 'invalid_token',
  );

  const family = env.service.db
    .prepare('SELECT revoked_at_ms, revoke_reason FROM token_families')
    .get();
  assert.ok(family.revoked_at_ms !== null);
  env.close();
});

test('跨两个服务实例（独立连接）并发刷新：写锁 + 条件 UPDATE 保证原子', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);

  // 两个实例共享同一数据库文件（模拟多实例部署），各自独立连接
  const clockA = new FakeClock(env.clock.now());
  const clockB = new FakeClock(env.clock.now());

  const gate = new Gate();
  const svc1 = openAnotherService(env.dbPath, clockA, {
    hooks: {
      afterConsume: async () => {
        await gate.enter(); // 实例1 先消费旧令牌，然后停在持锁临界点
      },
    },
  });
  const svc2 = openAnotherService(env.dbPath, clockB, {
    hooks: {
      afterConsume: async () => {
        await gate.enter();
      },
    },
  });

  // p1 先起跑，确保它先拿到写锁并完成原子消费
  const p1 = settle(
    svc1.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
  );
  await gate.waitFor(1);

  // 此时 p1 持锁停在临界区；p2 在锁外排队（BEGIN IMMEDIATE 忙等待重试）
  const p2Promise = settle(
    svc2.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
  );
  // 给 p2 几轮忙重试，证明它确实经历了锁冲突而不是直接读到旧状态
  await new Promise((r) => setTimeout(r, 30));
  assert.ok(svc2.db.busyRetries >= 1, `期望发生锁冲突重试，实际 ${svc2.db.busyRetries}`);

  gate.open();
  const [r1, r2] = await Promise.all([p1, p2Promise]);

  assert.equal(r1.ok, true, '先到的实例成功');
  assert.equal(r2.ok, false, '后到的实例失败（令牌已被消费）');
  assert.match(r2.error.message, /重放/);

  // 家族已撤销；r1 拿到的最新令牌同样作废
  const family = svc1.db
    .prepare('SELECT revoked_at_ms FROM token_families WHERE id=?')
    .get(t0.familyId);
  assert.ok(family.revoked_at_ms !== null);

  svc1.close();
  svc2.close();
  env.close();
});

test('跨客户端使用刷新令牌：B 不能刷新 A 的令牌', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service, CLIENT_A);

  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_B.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_grant' && /客户端不匹配/.test(e.message),
  );

  // 跨客户端尝试不属于重放攻击（提交者不是所有者），A 的令牌仍然有效
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.ok(t1.accessToken);
  env.close();
});

test('访问令牌到期后不可用；刷新令牌到期后不能再轮换', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);

  env.clock.tick(60 * 60 * 1000 + 1); // 访问令牌过期
  await assert.rejects(
    env.service.introspectAccessToken(t0.accessToken),
    (e) => e.error === 'invalid_token' && /过期/.test(e.message),
  );

  // 刷新令牌还没过期（默认 30 天），可以换取新访问令牌
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.ok(t1.accessToken);

  // 把刷新令牌也推到过期
  env.clock.tick(30 * 24 * 60 * 60 * 1000);
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t1.refreshToken,
    }),
    (e) => e.error === 'invalid_grant' && /刷新令牌已过期/.test(e.message),
  );
  env.close();
});

test('重启后轮换状态与撤销状态均持久：旧刷新令牌继续被拒，家族仍处于撤销态', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t0.refreshToken,
  });
  // 重放 t0 触发家族撤销
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
    () => true,
  );
  env.close();

  const clock2 = new FakeClock(env.clock.now() + 60_000);
  const restarted = openAnotherService(env.dbPath, clock2);

  // 重启前轮换出的最新令牌在重启后仍然无效
  await assert.rejects(
    restarted.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t1.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );
  await assert.rejects(
    restarted.introspectAccessToken(t1.accessToken),
    (e) => e.error === 'invalid_token',
  );

  // 另一条正常轮换链在重启后应仍然可用（证明持久化不会误杀未撤销家族）
  const healthy = await makeService({ dbPath: tempDbPath() });
  const s0 = await firstTokens(healthy.service);
  const savedNow = healthy.clock.now();
  healthy.close();

  const clock3 = new FakeClock(savedNow + 1_000);
  const restarted2 = openAnotherService(healthy.dbPath, clock3);
  const s1 = await restarted2.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: s0.refreshToken,
  });
  assert.ok(s1.accessToken);
  restarted2.close();
});
