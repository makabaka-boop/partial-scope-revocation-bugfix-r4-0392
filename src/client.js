'use strict';

const http = require('node:http');
const {
  generateCodeVerifier,
  computeCodeChallenge,
} = require('./crypto');

/**
 * 模拟客户端 SDK：演示一个客户端如何走完整授权码 + PKCE 流程。
 * 客户端在发起授权前先生成随机验证值，只把摘要（challenge）交给授权服务。
 */
class MockOAuthClient {
  /**
   * @param {object} opts
   * @param {string} opts.baseUrl 授权服务地址，如 http://127.0.0.1:3000
   * @param {string} opts.clientId
   * @param {string} opts.redirectUri 事先登记的精确回调地址
   */
  constructor({ baseUrl, clientId, redirectUri }) {
    this.baseUrl = baseUrl;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
  }

  /**
   * 发起授权：生成 PKCE 验证值 + 挑战。
   * 真实系统中这里应是把用户浏览器重定向到 /authorize；演示中直接返回参数，
   * 由“用户/授权页”带着 challenge 去请求签发授权码。
   */
  startAuthorization() {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = computeCodeChallenge(codeVerifier, 'S256');
    return {
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      codeChallenge,
      codeChallengeMethod: 'S256',
      codeVerifier, // 仅客户端本地持有
    };
  }

  /** 用授权码 + 本地保存的验证值兑换令牌。 */
  async exchangeCode(code, codeVerifier, redirectUri = this.redirectUri) {
    return this._post('/token', {
      grantType: 'authorization_code',
      clientId: this.clientId,
      code,
      redirectUri,
      codeVerifier,
    });
  }

  async refresh(refreshToken, scopes) {
    return this._post('/token', {
      grantType: 'refresh_token',
      clientId: this.clientId,
      refreshToken,
      scopes,
    });
  }

  async callResource(accessToken) {
    return this._post('/introspect', { accessToken });
  }

  async _post(path, payload) {
    const body = Buffer.from(JSON.stringify(payload));
    return new Promise((resolve, reject) => {
      const req = http.request(
        this.baseUrl + path,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'content-length': body.length,
          },
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed;
            try {
              parsed = text ? JSON.parse(text) : {};
            } catch {
              parsed = { error: 'bad_response', error_description: text };
            }
            if (res.statusCode >= 400) {
              const err = new Error(parsed.error_description || parsed.error || `HTTP ${res.statusCode}`);
              err.statusCode = res.statusCode;
              err.body = parsed;
              return reject(err);
            }
            return resolve(parsed);
          });
        },
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }
}

module.exports = { MockOAuthClient };
