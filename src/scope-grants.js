'use strict';

/**
 * 每客户端、每范围的部分撤销状态（持久化在 scope_grants 表）。
 *
 * 两个维度：
 * - granted：该客户端当前是否持有该范围（true 授权 / false 撤销）；
 * - grant_version：授权纪元，每次 granted 状态真正翻转时 +1。
 *
 * 授权码（auth_code_scopes）与令牌家族（token_family_scopes）在签发时
 * 快照各自范围的 grant_version。凭据日后被使用时，某范围只有在
 *   “当前仍 granted 且 grant_version 与快照一致”
 * 的情况下才继续有效。于是：
 * - 撤销后，撤销前签发的旧码、旧访问/刷新凭据都无法再行使该范围；
 * - 撤销后再重新授权会推进纪元，旧凭据快照的版本对不上，
 *   被撤销过的范围不会随重新授权“复活”，只有之后新签发的凭据才带它；
 * - 状态按 (client_id, scope) 隔离并落盘：客户端之间互不连带，重启不复活。
 */
class ScopeGrants {
  /**
   * @param {import('./db').Db} db 所有方法都假定在调用方的事务/连接上执行
   */
  constructor(db) {
    this.db = db;
  }

  /**
   * 登记客户端时为其开放的范围补齐默认授权行（granted=1, version=1）。
   * 已存在的行一律不动——重复登记不能把已撤销的范围悄悄复活。
   * 必须在写事务内调用。
   */
  async ensureForClient(clientId, scopes) {
    for (const scope of scopes) {
      await this.db.run(
        `INSERT OR IGNORE INTO scope_grants
           (client_id, scope, granted, grant_version, updated_at_ms)
         VALUES (?, ?, 1, 1, 0)`,
        [clientId, scope],
      );
    }
  }

  /**
   * 撤销（granted=false）或重新授权（granted=true）若干范围。
   * 仅当 granted 状态真正翻转时才把 grant_version +1；
   * 对同一状态重复设置是幂等的，不推进纪元（旧凭据不会因此被赦免或误伤）。
   * 必须在写事务内调用。
   *
   * @returns {Promise<string[]>} 实际发生状态翻转的范围
   */
  async set(clientId, scopes, granted, now) {
    const want = granted ? 1 : 0;
    const changed = [];
    for (const scope of scopes) {
      const row = await this.db.get(
        `SELECT granted, grant_version FROM scope_grants
         WHERE client_id = ? AND scope = ?`,
        [clientId, scope],
      );

      // 缺行（理论上 ensureForClient 已补齐）按“默认已授权 v1”兜底
      if (!row) {
        await this.db.run(
          `INSERT INTO scope_grants
             (client_id, scope, granted, grant_version, updated_at_ms)
           VALUES (?, ?, ?, ?, ?)`,
          // 默认态 granted=1/v1；撤销算一次翻转 => v2；重新授权与默认态相同 => v1
          [clientId, scope, want, want === 0 ? 2 : 1, now],
        );
        if (want === 0) changed.push(scope);
        continue;
      }

      const isGranted = row.granted === 1;
      if ((want === 1) !== isGranted) {
        await this.db.run(
          `UPDATE scope_grants
              SET granted = ?, grant_version = ?, updated_at_ms = ?
            WHERE client_id = ? AND scope = ?`,
          [want, row.grant_version + 1, now, clientId, scope],
        );
        changed.push(scope);
      }
    }
    return changed;
  }

  /**
   * 读取若干范围当前的授权状态快照。
   * @returns {Promise<Map<string,{granted:boolean, version:number}>>}
   * 表中缺行的已登记范围按默认“已授权 v1”兜底。
   */
  async current(clientId, scopes) {
    const result = new Map();
    if (scopes.length === 0) return result;
    const placeholders = scopes.map(() => '?').join(',');
    const rows = await this.db.all(
      `SELECT scope, granted, grant_version FROM scope_grants
       WHERE client_id = ? AND scope IN (${placeholders})`,
      [clientId, ...scopes],
    );
    for (const scope of scopes) {
      const row = rows.find((r) => r.scope === scope);
      result.set(
        scope,
        row
          ? { granted: row.granted === 1, version: row.grant_version }
          : { granted: true, version: 1 },
      );
    }
    return result;
  }
}

module.exports = { ScopeGrants };
