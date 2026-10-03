'use strict';

const { AuthError } = require('./errors');

/**
 * 极简 HTTP 适配层（无第三方依赖）：
 * 把授权服务的方法映射为 JSON POST 接口，统一错误为 OAuth 风格响应。
 *
 * 路由：
 *   POST /authorize      用户确认授权范围后签发授权码（模拟授权页 + 同意）
 *   POST /token          grant_type=authorization_code | refresh_token
 *   POST /introspect     校验访问令牌
 *   POST /revoke         撤销令牌家族
 */
function createJsonServer(authService) {
  // eslint-disable-next-line global-require
  const http = require('node:http');

  const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST') {
      return sendJson(res, 405, { error: 'method_not_allowed' });
    }
    try {
      const body = await readJson(req);
      let result;
      switch (req.url) {
        case '/authorize':
          result = await authService.issueAuthorizationCode(body);
          break;
        case '/token':
          result = await handleToken(body);
          break;
        case '/introspect':
          result = await authService.introspectAccessToken(body.accessToken);
          break;
        case '/scope-grant':
          result=await authService.setScopeGrant(body);
          break;
        case '/revoke':
          await authService.revokeFamily(body.familyId, body.reason || 'manual');
          result = { ok: true };
          break;
        default:
          return sendJson(res, 404, { error: 'not_found' });
      }
      return sendJson(res, 200, result);
    } catch (e) {
      if (e instanceof AuthError) {
        return sendJson(res, e.status, { error: e.error, error_description: e.message });
      }
      return sendJson(res, 500, { error: 'server_error', error_description: String(e && e.message) });
    }
  });

  async function handleToken(body) {
    if (body.grantType === 'authorization_code' || body.grant_type === 'authorization_code') {
      return authService.exchangeAuthorizationCode({
        clientId: body.clientId ?? body.client_id,
        code: body.code,
        redirectUri: body.redirectUri ?? body.redirect_uri,
        codeVerifier: body.codeVerifier ?? body.code_verifier,
      });
    }
    if (body.grantType === 'refresh_token' || body.grant_type === 'refresh_token') {
      return authService.refreshAccessToken({
        clientId: body.clientId ?? body.client_id,
        refreshToken: body.refreshToken ?? body.refresh_token,
        scopes: body.scopes,
      });
    }
    throw new AuthError('unsupported_grant_type', `不支持的 grant_type: ${body.grantType}`);
  }

  return server;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) reject(new AuthError('invalid_request', '请求体过大', 413));
      chunks.push(c);
    });
    req.on('end', () => {
      if (chunks.length === 0) return resolve({});
      try {
        return resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        return reject(new AuthError('invalid_request', '请求体不是合法 JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  const buf = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': buf.length,
  });
  res.end(buf);
}

module.exports = { createJsonServer };
