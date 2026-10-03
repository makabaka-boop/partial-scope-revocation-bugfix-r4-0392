'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  makeService,
  openAnotherService,
  CLIENT_A,
  Gate,
  settle,
} = require('./helpers');
const { FakeClock } = require('../src/clock');
const {
  generateCodeVerifier,
  computeCodeChallenge,
} = require('../src/crypto');

/** 签发一张授权码，返回兑换所需参数。 */
async function issueOne(service, client = CLIENT_A) {
  const verifier = generateCodeVerifier();
  const challenge = computeCodeChallenge(verifier, 'S256');
  const { code } = await service.issueAuthorizationCode({
    clientId: client.clientId,
    redirectUri: client.redirectUris[0],
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    scopes: ['read:profile'],
  });
  return {
    code,
    verifier,
    exchange: {
      clientId: client.clientId,
      code,
      redirectUri: client.redirectUris[0],
      codeVerifier: verifier,
    },
  };
}

test('并发兑换同一授权码（单实例）：恰好一个成功，绝不发两组令牌', async () => {
  const env = await makeService();
  const one = await issueOne(env.service);

  const [r1, r2] = await Promise.all([
    settle(env.service.exchangeAuthorizationCode(one.exchange)),
    settle(env.service.exchangeAuthorizationCode(one.exchange)),
  ]);

  assert.notEqual(r1.ok, r2.ok, '一个成功一个失败');
  const familyCount = env.service.db
    .prepare('SELECT COUNT(*) c FROM token_families')
    .get().c;
  const accessCount = env.service.db
    .prepare('SELECT COUNT(*) c FROM access_tokens')
    .get().c;
  assert.equal(familyCount, 1, '只有一个家族');
  assert.equal(accessCount, 1, '只发出一张访问令牌');
  env.close();
});

test('并发兑换（两个独立连接/实例，真实写锁交错）：后到者等待锁后看到已消费状态', async () => {
  const env = await makeService();
  const one = await issueOne(env.service);

  const gate = new Gate();
  const clockA = new FakeClock(env.clock.now());
  const clockB = new FakeClock(env.clock.now());
  const svc1 = openAnotherService(env.dbPath, clockA, {
    hooks: { afterConsume: async () => gate.enter() },
  });
  const svc2 = openAnotherService(env.dbPath, clockB, {
    hooks: { afterConsume: async () => gate.enter() },
  });

  const p1 = settle(svc1.exchangeAuthorizationCode(one.exchange));
  await gate.waitFor(1); // svc1 已在事务内原子消费授权码，仍持写锁

  // svc2 此时启动：BEGIN IMMEDIATE 拿不到锁，进入忙等待重试
  const p2 = settle(svc2.exchangeAuthorizationCode(one.exchange));
  await new Promise((r) => setTimeout(r, 30));
  assert.ok(
    svc2.db.busyRetries >= 1,
    `期望至少一次锁冲突重试，实际 ${svc2.db.busyRetries}`,
  );

  gate.open();
  const [r1, r2] = await Promise.all([p1, p2]);

  assert.equal(r1.ok, true, '先到者兑换成功');
  assert.equal(r2.ok, false, '后到者兑换失败');
  assert.equal(r2.error.error, 'invalid_grant');
  assert.match(r2.error.message, /已被兑换/);

  // 全库仍只有一组令牌
  const counts = svc1.db
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM token_families) AS families,
         (SELECT COUNT(*) FROM access_tokens)  AS accesses,
         (SELECT COUNT(*) FROM refresh_tokens) AS refreshes,
         (SELECT COUNT(*) FROM auth_codes WHERE redeemed_at_ms IS NULL) AS live_codes`,
    )
    .get();
  assert.deepEqual(counts, {
    families: 1,
    accesses: 1,
    refreshes: 1,
    live_codes: 0,
  });

  svc1.close();
  svc2.close();
  env.close();
});

test('并发兑换不同授权码互不干扰：两张码各自成功', async () => {
  const env = await makeService();
  const one = await issueOne(env.service);
  const two = await issueOne(env.service);

  const [r1, r2] = await Promise.all([
    settle(env.service.exchangeAuthorizationCode(one.exchange)),
    settle(env.service.exchangeAuthorizationCode(two.exchange)),
  ]);
  assert.equal(r1.ok, true, r1.ok ? '' : r1.error.message);
  assert.equal(r2.ok, true, r2.ok ? '' : r2.error.message);
  assert.equal(
    env.service.db.prepare('SELECT COUNT(*) c FROM token_families').get().c,
    2,
  );
  env.close();
});
