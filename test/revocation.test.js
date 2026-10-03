'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeService, CLIENT_A } = require('./helpers');
const { generateCodeVerifier, computeCodeChallenge } = require('../src/crypto');

async function firstTokens(service) {
  const verifier = generateCodeVerifier();
  const { code } = await service.issueAuthorizationCode({
    clientId: CLIENT_A.clientId,
    redirectUri: CLIENT_A.redirectUris[0],
    codeChallenge: computeCodeChallenge(verifier, 'S256'),
    scopes: ['read:profile'],
  });
  return service.exchangeAuthorizationCode({
    clientId: CLIENT_A.clientId,
    code,
    redirectUri: CLIENT_A.redirectUris[0],
    codeVerifier: verifier,
  });
}

test('未知 / 空访问令牌被拒', async () => {
  const env = await makeService();
  await assert.rejects(
    env.service.introspectAccessToken('not-a-real-token'),
    (e) => e.error === 'invalid_token' && e.status === 401,
  );
  await assert.rejects(
    env.service.introspectAccessToken(''),
    (e) => e.error === 'invalid_token',
  );
  env.close();
});

test('手动撤销家族（登出）后访问令牌与刷新令牌均失效', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);

  await env.service.revokeFamily(t0.familyId, 'logout');

  await assert.rejects(
    env.service.introspectAccessToken(t0.accessToken),
    (e) => e.error === 'invalid_token' && /家族撤销/.test(e.message),
  );
  await assert.rejects(
    env.service.refreshAccessToken({
      clientId: CLIENT_A.clientId,
      refreshToken: t0.refreshToken,
    }),
    (e) => e.error === 'invalid_grant',
  );

  const family = await env.service.db.get('SELECT revoke_reason FROM token_families WHERE id = ?', [t0.familyId]);
  assert.equal(family.revoke_reason, 'logout');
  env.close();
});

test('撤销是幂等的：重复撤销不报错，原因保留为第一次', async () => {
  const env = await makeService();
  const t0 = await firstTokens(env.service);
  await env.service.revokeFamily(t0.familyId, 'first');
  await env.service.revokeFamily(t0.familyId, 'second');
  const family = await env.service.db.get('SELECT revoke_reason FROM token_families WHERE id = ?', [t0.familyId]);
  assert.equal(family.revoke_reason, 'first');
  env.close();
});
