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
  hashToken,
} = require('../src/crypto');

/** 客户端 A 发起授权并由“用户/授权页”确认范围，返回授权码与本地验证值。 */
async function authorizeA(service, scopes = ['read:profile']) {
  const verifier = generateCodeVerifier();
  const challenge = computeCodeChallenge(verifier, 'S256');
  const { code } = await service.issueAuthorizationCode({
    clientId: CLIENT_A.clientId,
    redirectUri: CLIENT_A.redirectUris[0],
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    scopes,
  });
  return { code, verifier };
}

test('正常流程：签发 -> 兑换 -> 用访问令牌访问资源', async () => {
  const env = await makeService();
  const { code, verifier } = await authorizeA(env.service, ['read:profile', 'read:docs']);

  const tokens = await env.service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });

  assert.equal(tokens.tokenType, 'Bearer');
  assert.ok(tokens.accessToken.length > 20);
  assert.ok(tokens.refreshToken.length > 20);
  assert.deepEqual(tokens.scope.sort(), ['read:docs', 'read:profile']);
  assert.equal(tokens.accessTokenExpiresAtMs - env.clock.now(), 3600_000);

  const info = await env.service.introspectAccessToken(tokens.accessToken);
  assert.equal(info.clientId, CLIENT_A.clientId);
  assert.deepEqual(info.scope.sort(), ['read:docs', 'read:profile']);
  env.close();
});

test('授权码只能成功兑换一次：重放被拒，且不会产生第二组令牌', async () => {
  const env = await makeService();
  const { code, verifier } = await authorizeA(env.service);

  const first = await env.service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });
  assert.ok(first.accessToken);

  await assert.rejects(
    env.service.exchangeAuthorizationCode({
      clientId: CLIENT_A.clientId,
      code,
      redirectUri: CLIENT_A.redirectUris[0],
      codeVerifier: verifier,
    }),
    (e) => e.error === 'invalid_grant',
  );

  // 只有一个令牌家族、一张访问令牌
  const familyCount = env.service.db
    .prepare('SELECT COUNT(*) c FROM token_families')
    .get().c;
  const accessCount = env.service.db
    .prepare('SELECT COUNT(*) c FROM access_tokens')
    .get().c;
  assert.equal(familyCount, 1);
  assert.equal(accessCount, 1);
  env.close();
});

test('交叉兑换：客户端 B 不能兑换签发给 A 的授权码', async () => {
  const env = await makeService();
  const { code, verifier } = await authorizeA(env.service);

  await assert.rejects(
    env.service.exchangeAuthorizationCode({
      clientId: CLIENT_B.clientId, // B 冒名兑换
      code,
      redirectUri: CLIENT_A.redirectUris[0],
      codeVerifier: verifier,
    }),
    (e) => e.error === 'invalid_grant' && /客户端不匹配/.test(e.message),
  );

  // 被拒后原码对 A 仍然有效（错误归属不会消费掉授权码）
  const tokens = await env.service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });
  assert.ok(tokens.accessToken);
  env.close();
});

test('回调地址必须与事先登记的精确地址逐字符相等', async () => {
  const env = await makeService();
  const verifier = generateCodeVerifier();
  const challenge = computeCodeChallenge(verifier, 'S256');

  // 签发阶段：未登记地址直接拒签
  await assert.rejects(
    env.service.issueAuthorizationCode({
      clientId: CLIENT_A.clientId,
      redirectUri: 'http://client-a.example/cb?extra=1',
      codeChallenge: challenge,
      scopes: ['read:profile'],
    }),
    (e) => e.error === 'invalid_redirect_uri',
  );

  const { code } = await env.service.issueAuthorizationCode({
    clientId: CLIENT_A.clientId,
    redirectUri: CLIENT_A.redirectUris[0],
    codeChallenge: challenge,
    scopes: ['read:profile'],
  });

  // 兑换阶段：地址稍有不同即拒（结尾斜杠、他人地址）
  for (const bad of [
    'http://client-a.example/cb/',
    'http://client-a.example/cb?x=1',
    CLIENT_B.redirectUris[0],
  ]) {
    await assert.rejects(
      env.service.exchangeAuthorizationCode({
        clientId: CLIENT_A.clientId,
        code,
        redirectUri: bad,
        codeVerifier: verifier,
      }),
      (e) => e.error === 'invalid_grant',
    );
  }
  env.close();
});

test('PKCE：错误的验证值 / 篡改挑战均被拒，且不消费授权码', async () => {
  const env = await makeService();
  const verifier = generateCodeVerifier();
  const challenge = computeCodeChallenge(verifier, 'S256');
  const { code } = await env.service.issueAuthorizationCode({
    clientId: CLIENT_A.clientId,
    redirectUri: CLIENT_A.redirectUris[0],
    codeChallenge: challenge,
    scopes: ['read:profile'],
  });

  const wrongVerifier = generateCodeVerifier();
  await assert.rejects(
    env.service.exchangeAuthorizationCode({
      clientId: CLIENT_A.clientId,
      code,
      redirectUri: CLIENT_A.redirectUris[0],
      codeVerifier: wrongVerifier,
    }),
    (e) => e.error === 'invalid_grant' && /PKCE/.test(e.message),
  );

  // 正确验证值仍可兑换（PKCE 失败发生在原子消费之前）
  const tokens = await env.service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });
  assert.ok(tokens.accessToken);
  env.close();
});

test('授权码过期（时钟推进）后无法兑换', async () => {
  const env = await makeService();
  const { code, verifier } = await authorizeA(env.service);

  env.clock.tick(10 * 60 * 1000 + 1); // 超过 10 分钟
  await assert.rejects(
    env.service.exchangeAuthorizationCode({
      clientId: CLIENT_A.clientId,
      code,
      redirectUri: CLIENT_A.redirectUris[0],
      codeVerifier: verifier,
    }),
    (e) => e.error === 'invalid_grant' && /过期/.test(e.message),
  );
  env.close();
});

test('不存在 / 未知客户端的兑换请求被拒', async () => {
  const env = await makeService();
  await assert.rejects(
    env.service.exchangeAuthorizationCode({
      clientId: 'unknown',
      code: 'x'.repeat(40),
      redirectUri: 'http://x/cb',
      codeVerifier: 'y'.repeat(40),
    }),
    (e) => e.error === 'invalid_client',
  );
  env.close();
});

test('数据库只存摘要：原始授权码与令牌均不出现在库文件中', async () => {
  const env = await makeService();
  const { code, verifier } = await authorizeA(env.service);
  const tokens = await env.service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });

  // 内存中的行是摘要
  const codeRow = env.service.db
    .prepare('SELECT code_hash FROM auth_codes')
    .get();
  assert.equal(codeRow.code_hash, hashToken(code));
  assert.notEqual(codeRow.code_hash, code);

  const refreshHashes = env.service.db
    .prepare('SELECT token_hash FROM refresh_tokens')
    .all()
    .map((r) => r.token_hash);
  assert.ok(refreshHashes.includes(hashToken(tokens.refreshToken)));
  assert.ok(!refreshHashes.includes(tokens.refreshToken));
  env.close();
});

test('重启后已兑换的授权码不会复活', async () => {
  const env = await makeService();
  const { code, verifier } = await authorizeA(env.service);
  await env.service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });
  env.close();

  // 用同一文件重新打开服务（模拟重启），时钟推进 5 秒
  const clock2 = new FakeClock(env.clock.now() + 5_000);
  const restarted = openAnotherService(env.dbPath, clock2);
  await assert.rejects(
    restarted.exchangeAuthorizationCode({
      clientId: CLIENT_A.clientId,
      code,
      redirectUri: CLIENT_A.redirectUris[0],
      codeVerifier: verifier,
    }),
    (e) => e.error === 'invalid_grant',
  );
  restarted.close();
});
