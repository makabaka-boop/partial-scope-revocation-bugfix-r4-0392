'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  makeService,
  CLIENT_A,
  CLIENT_B,
} = require('./helpers');
const {
  generateCodeVerifier,
  computeCodeChallenge,
} = require('../src/crypto');

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

test('范围越权：客户端不能申请未对其开放的范围', async () => {
  const env = await makeService();

  // CLIENT_A 允许 read:profile/read:docs，请求 write:docs 必须在签发阶段拒绝
  await assert.rejects(
    issue(env.service, CLIENT_A, ['read:profile', 'write:docs']),
    (e) => e.error === 'invalid_scope',
  );

  // 空范围也不允许
  await assert.rejects(
    env.service.issueAuthorizationCode({
      clientId: CLIENT_A.clientId,
      redirectUri: CLIENT_A.redirectUris[0],
      codeChallenge: computeCodeChallenge(generateCodeVerifier(), 'S256'),
      scopes: [],
    }),
    (e) => e.error === 'invalid_scope',
  );
  env.close();
});

test('令牌携带的范围仅限用户确认并允许的范围（即使客户端想要更多）', async () => {
  const env = await makeService();

  // A 虽然同时拥有 read:profile 和 read:docs，但本次用户只确认 read:docs
  const granted = await issue(env.service, CLIENT_A, ['read:docs']);
  const tokens = await granted.exchange();
  assert.deepEqual(tokens.scope, ['read:docs']);

  const info = await env.service.introspectAccessToken(tokens.accessToken);
  assert.deepEqual(info.scope, ['read:docs']);
  env.close();
});

test('刷新时不能提权：请求超集范围 / 其他范围被 invalid_scope 拒绝', async () => {
  const env = await makeService();
  // A 的两个允许范围都在家族里
  const granted = await issue(env.service, CLIENT_A, ['read:profile', 'read:docs']);
  const t0 = await granted.exchange();

  // 想借刷新扩大范围 —— 拒绝
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
      scopes: ['read:profile', 'read:docs', 'write:docs'],
    }),
    (e) => e.error === 'invalid_scope',
  );

  // 想借刷新换成别的范围（即便另一个范围也对该客户端开放）——拒绝，且不发生轮换
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
      scopes: ['read:profile'],
    }),
    (e) => e.error === 'invalid_scope',
  );

  // 被拒后原刷新令牌仍可正常使用（范围校验失败不消费令牌）
  const t1 = await env.service.refreshAccessToken({
    clientId: CLIENT_A.clientId,
    refreshToken: t0.refreshToken,
  });
  assert.deepEqual(t1.scope.sort(), ['read:docs', 'read:profile']);
  env.close();
});

test('两客户端范围隔离：B 的 write:docs 对 A 不可用，反之亦然', async () => {
  const env = await makeService();

  await assert.rejects(issue(env.service, CLIENT_A, ['write:docs']), (e) =>
    e.error === 'invalid_scope');
  await assert.rejects(issue(env.service, CLIENT_B, ['read:docs']), (e) =>
    e.error === 'invalid_scope');

  // 各自在允许范围内正常
  const a = await issue(env.service, CLIENT_A, ['read:docs']);
  const b = await issue(env.service, CLIENT_B, ['write:docs']);
  const ta = await a.exchange();
  const tb = await b.exchange();
  assert.deepEqual(ta.scope, ['read:docs']);
  assert.deepEqual(tb.scope, ['write:docs']);
  assert.notEqual(ta.familyId, tb.familyId);
  env.close();
});
