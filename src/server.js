'use strict';

const {ScopeGrants}=require('./scope-grants');
const { Db, migrate } = require('./db');
const { Clock } = require('./clock');
const { AuthError } = require('./errors');
const {
  generateOpaque,
  hashToken,
  generateCodeVerifier,
  computeCodeChallenge,
  safeEqual,
} = require('./crypto');

const DEFAULT_TTLS = {
  codeTtlMs: 10 * 60 * 1000, // 授权码：10 分钟
  accessTokenTtlMs: 60 * 60 * 1000, // 访问令牌：1 小时
  refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000, // 刷新令牌：30 天
};

/**
 * 授权服务（授权码模式 + PKCE）。
 *
 * 安全性质：
 * 1. 授权码绑定 client_id、精确登记的 redirect_uri、PKCE 挑战（客户端提交的是验证值摘要）；
 * 2. 授权码只能成功兑换一次——由条件 UPDATE 在写事务内原子消费保证；
 * 3. 访问令牌有到期时间；刷新令牌每次使用都轮换；
 * 4. 已用过的刷新令牌再次出现 => 撤销整个令牌家族（含最新令牌）；
 * 5. 所有到期判断走可注入时钟；
 * 6. 兑换/轮换/撤销在并发下原子（互斥锁 + BEGIN IMMEDIATE + 条件 UPDATE）；
 * 7. 所有状态持久化，重启不丢失、旧码/旧令牌不会复活；数据库只存摘要。
 */
class AuthService {
  /**
   * @param {object} opts
   * @param {string|import('./db').Db} opts.db 数据库文件路径或已构造的 Db
   * @param {import('./clock').Clock} [opts.clock]
   * @param {{codeTtlMs?:number, accessTokenTtlMs?:number, refreshTokenTtlMs?:number}} [opts.ttls]
   * @param {{afterConsume?:(event:object)=>Promise<void>|void}} [opts.hooks]
   *        测试钩子：写事务内、一次性凭据已原子消费之后、新令牌写入之前调用，
   *        此时仍持有写锁，可用于确定性地制造并发交错。
   */
  constructor({ db, clock, ttls = {}, hooks = {} } = {}) {
    this.db = typeof db === 'string' ? new Db(db) : db;
    this.clock = clock || new Clock();
    this.ttls = { ...DEFAULT_TTLS, ...ttls };
    this.hooks = hooks;
    migrate(this.db);
    this.grants=new ScopeGrants(this.db);
  }

  close() {
    this.db.close();
  }

  // ---------- 客户端注册（模拟客户端事先登记） ----------

  /**
   * 登记客户端：精确回调地址（可多个）+ 允许申请的范围。
   * 幂等：同 client_id 重复登记会更新名称，并补齐 URI / 范围。
   */
  async registerClient({ clientId, name, redirectUris, scopes }) {
    if (!clientId || typeof clientId !== 'string') {
      throw new AuthError('invalid_client', '缺少 client_id');
    }
    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
      throw new AuthError('invalid_redirect_uri', '客户端必须登记至少一个精确回调地址');
    }
    const scopeList = normalizeScopes(scopes);
    const now = this.clock.now();

    await this.db.withImmediateTx(async () => {
      await this.db.run(
        `INSERT INTO clients (client_id, name, created_at_ms) VALUES (?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET name = excluded.name`,
        [clientId, name || clientId, now],
      );
      for (const uri of redirectUris) {
        await this.db.run(
          `INSERT OR IGNORE INTO client_redirect_uris (client_id, redirect_uri) VALUES (?, ?)`,
          [clientId, uri],
        );
      }
      for (const scope of scopeList) {
        await this.db.run(
          `INSERT OR IGNORE INTO client_scopes (client_id, scope) VALUES (?, ?)`,
          [clientId, scope],
        );
      }
    });
    return { clientId, redirectUris, scopes: scopeList };
  }

  async setScopeGrant({clientId,scopes,granted}) {
    if(typeof granted!=='boolean')throw new AuthError('invalid_request','granted 必须为布尔值');
    return this.db.withImmediateTx(async()=>{
      await this._getClientOrThrow(clientId);
      const list=await this._assertScopesAllowed(clientId,scopes);
      await this.grants.set(clientId,list,granted);
      return {clientId,scope:list,granted};
    });
  }

  // ---------- 用户确认授权范围后签发短期授权码 ----------

  /**
   * 用户在授权页确认权限范围后调用。
   *
   * @param {object} args
   * @param {string} args.clientId
   * @param {string} args.redirectUri 必须与事先登记的地址逐字符相等
   * @param {string} args.codeChallenge 客户端事先提交的随机验证值摘要（PKCE challenge）
   * @param {'S256'|'plain'} [args.codeChallengeMethod]
   * @param {string|string[]} args.scopes 用户确认的范围
   * @returns {Promise<{code:string, expiresInMs:number, scope:string[]}>}
   */
  async issueAuthorizationCode({
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod = 'S256',
    scopes,
  }) {
    const client = await this._getClientOrThrow(clientId);
    await this._assertRedirectUri(clientId, redirectUri);

    if (codeChallengeMethod !== 'S256' && codeChallengeMethod !== 'plain') {
      throw new AuthError(
        'invalid_request',
        `不支持的 code_challenge_method: ${codeChallengeMethod}`,
      );
    }
    if (!codeChallenge || typeof codeChallenge !== 'string') {
      throw new AuthError('invalid_request', '缺少 code_challenge');
    }

    const granted = await this._assertScopesAllowed(clientId, scopes);

    const code = generateOpaque(32);
    const now = this.clock.now();
    await this.db.withImmediateTx(async () => {
      await this.grants.authorize(clientId,granted);
      await this.db.run(
        `INSERT INTO auth_codes
           (code_hash, client_id, redirect_uri, code_challenge, code_challenge_method,
            scope, expires_at_ms, created_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          hashToken(code),
          client.client_id,
          redirectUri,
          codeChallenge,
          codeChallengeMethod,
          granted.join(' '),
          now + this.ttls.codeTtlMs,
          now,
        ],
      );
    });

    return { code, expiresInMs: this.ttls.codeTtlMs, scope: granted };
  }

  // ---------- 授权码兑换令牌 ----------

  /**
   * 兑换授权码。必须同时匹配：客户端、精确回调地址、PKCE 验证值。
   * 授权码只能成功兑换一次；过期或已兑换一律 invalid_grant。
   *
   * @param {object} args
   */
  async exchangeAuthorizationCode({
    clientId,
    code,
    redirectUri,
    codeVerifier,
  }) {
    if (!clientId) throw new AuthError('invalid_client', '缺少 client_id', 401);
    if (!code) throw new AuthError('invalid_grant', '缺少授权码');
    if (!redirectUri) throw new AuthError('invalid_grant', '缺少 redirect_uri');
    if (!codeVerifier) throw new AuthError('invalid_grant', '缺少 code_verifier');

    // 客户端必须存在
    await this._getClientOrThrow(clientId);

    const codeHash = hashToken(code);
    const now = this.clock.now();

    return this.db.withImmediateTx(async () => {
      const row = await this.db.get(
        `SELECT code_hash, client_id, redirect_uri, code_challenge,
                code_challenge_method, scope, expires_at_ms, redeemed_at_ms
         FROM auth_codes WHERE code_hash = ?`,
        [codeHash],
      );

      if (!row) throw new AuthError('invalid_grant', '授权码无效');
      if (row.redeemed_at_ms !== null) {
        // 重放已兑换的码：绝不二次发令牌
        throw new AuthError('invalid_grant', '授权码已被兑换');
      }
      if (row.expires_at_ms <= now) {
        throw new AuthError('invalid_grant', '授权码已过期');
      }
      // 客户端必须匹配：禁止 A 客户端用 B 的码兑换
      if (!safeEqual(row.client_id, clientId)) {
        throw new AuthError('invalid_grant', '授权码与客户端不匹配');
      }
      // 回调地址必须与签发时（即事先登记）的地址逐字符相等
      if (!safeEqual(row.redirect_uri, redirectUri)) {
        throw new AuthError('invalid_grant', '回调地址不匹配');
      }
      // PKCE：客户端提交的验证值摘要必须与登记的挑战一致
      const computed =
        row.code_challenge_method === 'plain'
          ? codeVerifier
          : computeCodeChallenge(codeVerifier, 'S256');
      if (!safeEqual(computed, row.code_challenge)) {
        throw new AuthError('invalid_grant', 'PKCE 验证失败');
      }

      // 原子消费：条件 UPDATE 的 changes===1 才算成功，杜绝并发双重兑换
      const consume = await this.db.run(
        `UPDATE auth_codes SET redeemed_at_ms = ?
         WHERE code_hash = ? AND redeemed_at_ms IS NULL`,
        [now, codeHash],
      );
      if (consume.changes !== 1) {
        throw new AuthError('invalid_grant', '授权码已被兑换');
      }

      const scopes = row.scope.split(' ').filter(Boolean);
      if (this.hooks.afterConsume) {
        await this.hooks.afterConsume({ kind: 'code', clientId, now });
      }
      return this._createTokensLocked(row.client_id, scopes, now);
    });
  }

  // ---------- 刷新令牌：轮换 + 重放即家族撤销 ----------

  /**
   * 用刷新令牌换取新的访问令牌与刷新令牌（轮换）。
   *
   * - 刷新令牌过期 / 不存在 / 已被使用 / 家族已撤销 => invalid_grant
   * - 令牌必须属于提交它的客户端（跨客户端使用同样拒绝）
   * - 已用过的刷新令牌再次出现 => 撤销整个家族，包括已轮换出的最新令牌
   * - 请求范围必须是家族原始范围的子集且完全一致才允许（不允许借刷新提权）
   */
  async refreshAccessToken({ clientId, refreshToken, scopes }) {
    if (!clientId) throw new AuthError('invalid_client', '缺少 client_id', 401);
    if (!refreshToken) throw new AuthError('invalid_grant', '缺少刷新令牌');

    await this._getClientOrThrow(clientId);

    const tokenHash = hashToken(refreshToken);
    const now = this.clock.now();

    return this.db.withImmediateTx(async () => {
      const row = await this.db.get(
        `SELECT rt.token_hash, rt.family_id, rt.expires_at_ms, rt.consumed_at_ms,
                f.client_id AS family_client_id, f.scope AS family_scope,
                f.revoked_at_ms, f.revoke_reason
         FROM refresh_tokens rt
         JOIN token_families f ON f.id = rt.family_id
         WHERE rt.token_hash = ?`,
        [tokenHash],
      );

      if (!row) throw new AuthError('invalid_grant', '刷新令牌无效');

      // 跨客户端使用：令牌不属于该客户端（不触发家族撤销，因为提交者不是所有者）
      if (!safeEqual(row.family_client_id, clientId)) {
        throw new AuthError('invalid_grant', '刷新令牌与客户端不匹配');
      }

      // 重放检测：令牌已被消费过 => 家族可能已被攻陷/客户端在重放 => 撤销整个家族
      if (row.consumed_at_ms !== null || row.revoked_at_ms !== null) {
        await this._revokeFamilyLocked(row.family_id, now, 'reused_refresh_token');
        throw new AuthError('invalid_grant', '检测到刷新令牌重放，令牌家族已撤销', 400, { commitAfterThrow: true });
      }

      if (row.expires_at_ms <= now) {
        // 过期不撤销家族（家族里可能还有更晚轮换出的有效令牌），仅拒绝
        throw new AuthError('invalid_grant', '刷新令牌已过期');
      }

      // 范围检查：刷新不得扩大授权范围；传入范围时必须与家族范围完全一致
      if (scopes !== undefined && scopes !== null) {
        const requested = normalizeScopes(scopes);
        const familyScopes = normalizeScopes(row.family_scope);
        if (!scopesEqualAsSet(requested, familyScopes)) {
          throw new AuthError('invalid_scope', '刷新请求的范围超出原始授权范围');
        }
      }

      // 原子消费当前刷新令牌
      const consume = await this.db.run(
        `UPDATE refresh_tokens SET consumed_at_ms = ?
         WHERE token_hash = ? AND consumed_at_ms IS NULL`,
        [now, tokenHash],
      );
      if (consume.changes !== 1) {
        // 并发下另一个事务抢先消费 => 视为重放，撤销整个家族（含最新令牌）
        await this._revokeFamilyLocked(row.family_id, now, 'reused_refresh_token');
        throw new AuthError('invalid_grant', '检测到刷新令牌重放，令牌家族已撤销', 400, { commitAfterThrow: true });
      }

      const scopesList = normalizeScopes(row.family_scope);

      if (this.hooks.afterConsume) {
        // 持锁期间插入确定性交错点（测试用）
        await this.hooks.afterConsume({
          kind: 'refresh',
          clientId,
          familyId: row.family_id,
          now,
        });
      }

      const tokens = await this._createTokensLocked(
        row.family_client_id,
        scopesList,
        now,
        row.family_id,
      );

      // 记录轮换链：旧令牌指向新令牌
      await this.db.run(
        `UPDATE refresh_tokens SET superseded_by_family_token_hash = ?
         WHERE token_hash = ?`,
        [hashToken(tokens.refreshToken), tokenHash],
      );

      return tokens;
    });
  }

  /**
   * 校验访问令牌（受保护资源调用）。
   * 家族被撤销后，其所有访问令牌立即失效。
   *
   * @returns {Promise<{clientId:string, scope:string[], expiresAtMs:number}>}
   */
  async introspectAccessToken(accessToken) {
    if (!accessToken) throw new AuthError('invalid_token', '缺少访问令牌', 401);
    const tokenHash = hashToken(accessToken);
    const now = this.clock.now();

    const row = await this.db.get(
      `SELECT at.scope, at.expires_at_ms, at.family_id,
              f.client_id, f.revoked_at_ms
       FROM access_tokens at
       JOIN token_families f ON f.id = at.family_id
       WHERE at.token_hash = ?`,
      [tokenHash],
    );

    if (!row) throw new AuthError('invalid_token', '访问令牌无效', 401);
    if (row.expires_at_ms <= now) {
      throw new AuthError('invalid_token', '访问令牌已过期', 401);
    }
    if (row.revoked_at_ms !== null) {
      throw new AuthError('invalid_token', '访问令牌已随家族撤销', 401);
    }
    return {
      clientId: row.client_id,
      scope: row.scope.split(' ').filter(Boolean),
      familyId: row.family_id,
      expiresAtMs: row.expires_at_ms,
    };
  }

  /** 主动撤销整个家族（登出等场景）。 */
  async revokeFamily(familyId, reason = 'manual') {
    const now = this.clock.now();
    await this.db.withImmediateTx(async () => {
      await this._revokeFamilyLocked(familyId, now, reason);
    });
  }

  // ---------- 事务内部使用的辅助方法 ----------

  /**
   * 在当前写事务内创建一个令牌家族（首次兑换）或向既有家族追加新令牌对（轮换）。
   * 必须在 withImmediateTx 的回调中调用（调用方负责 await）。
   */
  async _createTokensLocked(clientId, scopes, now, existingFamilyId = null) {
    let familyId = existingFamilyId;
    if (familyId === null) {
      const family = await this.db.run(
        `INSERT INTO token_families (client_id, scope, created_at_ms)
         VALUES (?, ?, ?)`,
        [clientId, scopes.join(' '), now],
      );
      familyId = family.lastInsertRowid;
    }

    const accessToken = generateOpaque(32);
    const refreshToken = generateOpaque(32);

    await this.db.run(
      `INSERT INTO access_tokens (token_hash, family_id, scope, expires_at_ms, created_at_ms)
       VALUES (?, ?, ?, ?, ?)`,
      [
        hashToken(accessToken),
        familyId,
        scopes.join(' '),
        now + this.ttls.accessTokenTtlMs,
        now,
      ],
    );

    await this.db.run(
      `INSERT INTO refresh_tokens (token_hash, family_id, expires_at_ms, created_at_ms)
       VALUES (?, ?, ?, ?)`,
      [hashToken(refreshToken), familyId, now + this.ttls.refreshTokenTtlMs, now],
    );

    return {
      tokenType: 'Bearer',
      accessToken,
      accessTokenExpiresAtMs: now + this.ttls.accessTokenTtlMs,
      expiresInMs: this.ttls.accessTokenTtlMs,
      refreshToken,
      refreshTokenExpiresAtMs: now + this.ttls.refreshTokenTtlMs,
      scope: scopes,
      familyId,
    };
  }

  /**
   * 撤销整个家族：幂等。
   * 撤销后家族内全部访问令牌（含最新的）与刷新令牌均不可用。
   * 必须在写事务内调用。
   */
  async _revokeFamilyLocked(familyId, now, reason) {
    await this.db.run(
      `UPDATE token_families
         SET revoked_at_ms = COALESCE(revoked_at_ms, ?),
             revoke_reason = COALESCE(revoke_reason, ?)
       WHERE id = ?`,
      [now, reason, familyId],
    );
    // 未消费的刷新令牌一律标记消费，使最新刷新令牌也无法再用
    await this.db.run(
      `UPDATE refresh_tokens SET consumed_at_ms = ?
       WHERE family_id = ? AND consumed_at_ms IS NULL`,
      [now, familyId],
    );
  }

  async _getClientOrThrow(clientId) {
    const client = await this.db.get(
      'SELECT client_id, name FROM clients WHERE client_id = ?',
      [clientId],
    );
    if (!client) {
      throw new AuthError('invalid_client', '未知客户端', 401);
    }
    return client;
  }

  async _assertRedirectUri(clientId, redirectUri) {
    const row = await this.db.get(
      `SELECT 1 AS ok FROM client_redirect_uris
       WHERE client_id = ? AND redirect_uri = ?`,
      [clientId, redirectUri],
    );
    if (!row) {
      throw new AuthError(
        'invalid_redirect_uri',
        '回调地址未事先登记或不是精确匹配',
      );
    }
  }

  /** 请求范围必须全部在客户端允许列表内；返回归一化后的授权范围。 */
  async _assertScopesAllowed(clientId, scopes) {
    const requested = normalizeScopes(scopes);
    if (requested.length === 0) {
      throw new AuthError('invalid_scope', '授权范围不能为空');
    }
    const allowed = (
      await this.db.all('SELECT scope FROM client_scopes WHERE client_id = ?', [clientId])
    ).map((r) => r.scope);
    for (const s of requested) {
      if (!allowed.includes(s)) {
        throw new AuthError('invalid_scope', `范围 "${s}" 未对该客户端开放`);
      }
    }
    return requested;
  }
}

/** 空格分隔字符串 / 数组 => 去重排序的数组（范围集合的次序无关比较）。 */
function normalizeScopes(scopes) {
  if (scopes === undefined || scopes === null) return [];
  const list = Array.isArray(scopes)
    ? scopes
    : String(scopes).split(/\s+/);
  return [...new Set(list.map((s) => String(s).trim()).filter(Boolean))].sort();
}

/** 比较两个范围集合（已归一化）。 */
function scopesEqualAsSet(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

module.exports = {
  AuthService,
  DEFAULT_TTLS,
  normalizeScopes,
  scopesEqualAsSet,
};
