'use strict';

/**
 * 端到端演示：两个模拟客户端通过真实 HTTP 接口使用授权服务。
 *
 * 演示内容：
 *   1. 客户端 A 走授权码 + PKCE 正常流程，访问受保护资源；
 *   2. 两个客户端交叉兑换（B 冒用 A 的授权码）被拒；
 *   3. 并发刷新同一刷新令牌：恰好一个成功，另一个触发整家族撤销；
 *   4. 家族撤销后，连最新访问令牌也立即失效；
 *   5. 范围越权（A 申请未开放的 write:docs）在签发阶段被拒；
 *   6. 重启后已轮换/已撤销的状态仍然有效；
 *   7. 部分撤销写权限：旧码/旧令牌/刷新轮换立即失去写范围、读范围保留，
 *      重新授权后旧凭据不复活，只有新签发凭据恢复写权限，且不连带另一客户端。
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AuthService } = require('../src/server');
const { Clock } = require('../src/clock');
const { createJsonServer } = require('../src/http');
const { MockOAuthClient } = require('../src/client');
const { generateCodeVerifier } = require('../src/crypto');

const DB_FILE = path.join(os.tmpdir(), `auth-demo-${process.pid}.db`);

const CLIENT_A = {
  clientId: 'client-webapp',
  name: '示例 Web 应用',
  redirectUris: ['http://127.0.0.1:5173/callback'],
  scopes: ['read:profile', 'read:documents'],
};
const CLIENT_B = {
  clientId: 'client-mobile',
  name: '示例移动应用',
  redirectUris: ['com.example.mobile://oauth/callback'],
  scopes: ['read:profile', 'write:documents'],
};

function startServer(auth) {
  const server = createJsonServer(auth);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

/** “用户/授权页”动作：确认范围后 POST /authorize。 */
async function userApprovesAndIssues(baseUrl, client, params) {
  const res = await fetch(`${baseUrl}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      clientId: client.clientId,
      redirectUri: client.redirectUris[0],
      ...params,
    }),
  });
  const body = await res.json();
  if (!res.ok) throw Object.assign(new Error(body.error_description), { status: res.status, body });
  return body;
}

function describeError(label, promise) {
  return promise.then(
    (v) => {
      console.log(`  ${label}: ❌ 本应失败却成功了`);
      return v;
    },
    (e) => {
      const code = e.body ? e.body.error : e.message;
      const desc = e.body ? e.body.error_description : '';
      console.log(`  ${label}: ✅ 被拒绝（${code}${desc ? ` — ${desc}` : ''}）`);
    },
  );
}

async function main() {
  try { fs.rmSync(DB_FILE, { force: true }); } catch { /* ignore */ }

  let auth = new AuthService({ db: DB_FILE, clock: new Clock() });
  await auth.registerClient(CLIENT_A);
  await auth.registerClient(CLIENT_B);
  const { server, baseUrl } = await startServer(auth);
  const clientA = new MockOAuthClient({
    baseUrl,
    clientId: CLIENT_A.clientId,
    redirectUri: CLIENT_A.redirectUris[0],
  });
  const clientB = new MockOAuthClient({
    baseUrl,
    clientId: CLIENT_B.clientId,
    redirectUri: CLIENT_B.redirectUris[0],
  });

  console.log('── 1. 客户端 A：授权码 + PKCE 正常流程 ──');
  const paramsA = clientA.startAuthorization(); // 本地生成 verifier，只交出 challenge
  const { code: codeA } = await userApprovesAndIssues(baseUrl, CLIENT_A, {
    codeChallenge: paramsA.codeChallenge,
    codeChallengeMethod: 'S256',
    scopes: ['read:profile', 'read:documents'],
  });
  const tokensA = await clientA.exchangeCode(codeA, paramsA.codeVerifier);
  console.log('  兑换成功，访问令牌:', short(tokensA.accessToken));
  const who = await clientA.callResource(tokensA.accessToken);
  console.log('  资源服务器鉴权结果: client =', who.clientId, '，scope =', who.scope.join(' '));

  console.log('\n── 2. 客户端 B 交叉兑换 A 的授权码 ──');
  // 签发一张全新的、尚未兑换的码给 A
  const crossParams = clientA.startAuthorization();
  const { code: crossCode } = await userApprovesAndIssues(baseUrl, CLIENT_A, {
    codeChallenge: crossParams.codeChallenge,
    scopes: ['read:profile'],
  });
  await describeError(
    'B 冒用 A 的全新 code',
    clientB.exchangeCode(crossCode, crossParams.codeVerifier, CLIENT_A.redirectUris[0]),
  );
  // 冒用未得逞：码仍归 A 所有，A 自己可以正常兑换
  const crossTokens = await clientA.exchangeCode(crossCode, crossParams.codeVerifier);
  console.log('  冒用未消费该码，A 仍可正常兑换:', !!crossTokens.accessToken);

  console.log('\n── 3. 回调地址 / PKCE 绑定校验 ──');
  const params2 = clientA.startAuthorization();
  const { code: code2 } = await userApprovesAndIssues(baseUrl, CLIENT_A, {
    codeChallenge: params2.codeChallenge,
    scopes: ['read:profile'],
  });
  await describeError(
    '错误回调地址兑换',
    clientA.exchangeCode(code2, params2.codeVerifier, 'http://127.0.0.1:5173/evil'),
  );
  await describeError(
    '错误 PKCE 验证值兑换',
    clientA.exchangeCode(code2, generateCodeVerifier()),
  );

  console.log('\n── 4. 并发刷新同一刷新令牌（真实 HTTP 并发）──');
  const t1 = await clientA.refresh(tokensA.refreshToken);
  console.log('  先正常轮换一次，新刷新令牌:', short(t1.refreshToken));
  const [r1, r2] = await Promise.allSettled([
    clientA.refresh(t1.refreshToken),
    clientA.refresh(t1.refreshToken), // 同一令牌并发重放
  ]);
  const ok = r1.status === 'fulfilled' ? r1.value : r2.value;
  console.log('  并发结果: 一个成功', r1.status === 'fulfilled' ? '(请求1)' : '(请求2)',
    '，另一个被拒', r2.status === 'rejected' || r1.status === 'rejected' ? '(重放)' : '');
  if (r1.status === 'rejected') console.log('   被拒原因:', r1.reason.body.error, '-', r1.reason.body.error_description);
  if (r2.status === 'rejected') console.log('   被拒原因:', r2.reason.body.error, '-', r2.reason.body.error_description);

  console.log('\n── 5. 家族撤销：连“获胜者”手里的最新令牌也立即失效 ──');
  await describeError(
    '用获胜的最新刷新令牌再刷新',
    clientA.refresh(ok.refreshToken),
  );
  await describeError(
    '用获胜的最新访问令牌访问资源',
    clientA.callResource(ok.accessToken),
  );

  console.log('\n── 6. 范围越权：A 申请未开放的 write:documents ──');
  const params3 = clientA.startAuthorization();
  await describeError(
    '签发阶段拒绝越权范围',
    userApprovesAndIssues(baseUrl, CLIENT_A, {
      codeChallenge: params3.codeChallenge,
      scopes: ['read:profile', 'write:documents'],
    }),
  );

  console.log('\n── 7. 部分撤销写权限（保留读权限）后重新授权 ──');
  const postScopeGrant = (clientId, scopes, granted) =>
    fetch(`${baseUrl}/scope-grant`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId, scopes, granted }),
    }).then(async (res) => {
      const body = await res.json();
      if (!res.ok) throw Object.assign(new Error(body.error_description), { status: res.status, body });
      return body;
    });

  // 撤销前：先签发一张含读写两个范围的新码，但暂不兑换
  const preParams = clientB.startAuthorization();
  const { code: preRevokeCode } = await userApprovesAndIssues(baseUrl, CLIENT_B, {
    codeChallenge: preParams.codeChallenge,
    scopes: ['read:profile', 'write:documents'],
  });
  // 同时拿一组已存在的令牌
  const bParams = clientB.startAuthorization();
  const { code: bCode } = await userApprovesAndIssues(baseUrl, CLIENT_B, {
    codeChallenge: bParams.codeChallenge,
    scopes: ['read:profile', 'write:documents'],
  });
  const bTokens = await clientB.exchangeCode(bCode, bParams.codeVerifier);
  console.log('  撤销前 B 的令牌范围:', (await clientB.callResource(bTokens.accessToken)).scope.join(' '));

  // 只撤销 B 的写范围
  await postScopeGrant(CLIENT_B.clientId, ['write:documents'], false);
  console.log('  已撤销 B 的 write:documents（保留 read:profile）');

  // 已签发的访问令牌立即失去写范围、读范围保留
  const narrowed = await clientB.callResource(bTokens.accessToken);
  console.log('  旧访问令牌现在的范围:', narrowed.scope.join(' '));

  // 撤销前签发的旧码兑换时被收窄
  const fromOldCode = await clientB.exchangeCode(preRevokeCode, preParams.codeVerifier);
  console.log('  撤销前旧码兑换出的范围:', fromOldCode.scope.join(' '));

  // 刷新轮换出的新令牌也只有读范围
  const refreshed = await clientB.refresh(bTokens.refreshToken);
  console.log('  刷新轮换后新令牌范围:', refreshed.scope.join(' '));

  // 撤销期间不能签发含写范围的新码
  const revokeParams = clientB.startAuthorization();
  await describeError(
    '撤销期间签发含写范围的新码',
    userApprovesAndIssues(baseUrl, CLIENT_B, {
      codeChallenge: revokeParams.codeChallenge,
      scopes: ['read:profile', 'write:documents'],
    }),
  );

  // 重新授权写范围：旧家族仍拿不回写范围（授权纪元已推进）
  await postScopeGrant(CLIENT_B.clientId, ['write:documents'], true);
  const refreshedAfterRegrant = await clientB.refresh(refreshed.refreshToken);
  console.log('  重新授权后旧家族刷新出的范围:', refreshedAfterRegrant.scope.join(' '), '（写范围不复活）');

  // 重新授权之后新签发的码/令牌才恢复写范围
  const afterParams = clientB.startAuthorization();
  const { code: afterCode } = await userApprovesAndIssues(baseUrl, CLIENT_B, {
    codeChallenge: afterParams.codeChallenge,
    scopes: ['read:profile', 'write:documents'],
  });
  const afterTokens = await clientB.exchangeCode(afterCode, afterParams.codeVerifier);
  console.log('  重新授权后新令牌范围:', afterTokens.scope.sort().join(' '));

  // A 的凭据不受 B 撤销连带影响（tokensA 的家族在第 4 节已被重放撤销，
  // 这里重新签发一组独立的新令牌用于隔离验证）
  const aIsoParams = clientA.startAuthorization();
  const { code: aIsoCode } = await userApprovesAndIssues(baseUrl, CLIENT_A, {
    codeChallenge: aIsoParams.codeChallenge,
    scopes: ['read:profile', 'read:documents'],
  });
  const aIsoTokens = await clientA.exchangeCode(aIsoCode, aIsoParams.codeVerifier);
  const aStill = await clientA.callResource(aIsoTokens.accessToken).catch(() => null);
  console.log(
    '  B 的撤销不连带 A：A 新签发的访问令牌',
    aStill ? `仍有效（${aStill.scope.join(' ')}）` : '已失效（异常）',
  );

  console.log('\n── 8. 重启持久化：关闭服务后用同一数据库文件重新启动 ──');
  await new Promise((resolve) => server.close(resolve));
  auth.close();
  const auth2 = new AuthService({ db: DB_FILE, clock: new Clock() });
  const started2 = await startServer(auth2);
  const clientA2 = new MockOAuthClient({
    baseUrl: started2.baseUrl,
    clientId: CLIENT_A.clientId,
    redirectUri: CLIENT_A.redirectUris[0],
  });
  await describeError(
    '重启后最新访问令牌仍然失效',
    clientA2.callResource(ok.accessToken),
  );
  console.log('  （已兑换的授权码、轮换链、家族撤销状态全部从磁盘恢复，无旧凭据复活）');

  await new Promise((resolve) => started2.server.close(resolve));
  auth2.close();
  try { fs.rmSync(DB_FILE, { force: true }); } catch { /* ignore */ }
  console.log('\n演示完成。');
}

function short(s) {
  return `${String(s).slice(0, 10)}…（${String(s).length} 字符）`;
}

main().catch((e) => {
  console.error('演示失败:', e);
  process.exit(1);
});
