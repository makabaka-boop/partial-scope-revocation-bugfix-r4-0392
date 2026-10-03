'use strict';

const { AuthError } = require('./errors');

/**
 * 序列化/解析“授权世代”快照。
 *
 * 每个（客户端, 范围）维护一个单调递增的世代 gen：
 *   - 从未撤销过（含旧库遗留凭据）：gen = 0（隐式授权基线）；
 *   - 每次 granted 状态翻转（授权 -> 撤销，或 撤销 -> 重新授权）gen += 1。
 *
 * 授权码与令牌家族在签发时固化自己的 {scope: gen} 快照；
 * 某范围对该凭据是否仍然有效，取决于当前世代是否仍等于快照世代。
 * 于是：
 *   - 撤销（gen 翻转）使所有撤销前凭据上的该范围立即失效，旧码/旧刷新令牌无法再取回；
 *   - 重新授权（gen 再翻转）只惠及之后签发的凭据，撤销前的旧快照仍停留在旧世代，不会恢复；
 *   - 状态按 (client_id, scope) 隔离且全部落盘，重启/多实例一致，不波及另一客户端。
 */
function serializeGens(map) {
  const entries = Object.keys(map)
    .sort()
    .map((scope) => [scope, map[scope]]);
  return JSON.stringify(entries);
}

function parseGens(json, scopes) {
  if (!json) {
    // 旧库遗留凭据：其范围内的范围全部视为 gen 0（撤销前基线，可被之后的撤销翻转掉）
    return Object.fromEntries(scopes.map((s) => [s, 0]));
  }
  return Object.fromEntries(JSON.parse(json));
}

class ScopeGrants {
  constructor(db) {
    this.db = db;
  }

  /**
   * 部分撤销 / 重新授权（仅针对给定客户端的给定范围）。
   * granted 与当前状态不同时 gen += 1；相同则幂等不动（世代不变）。
   * 必须在写事务内调用。
   */
  async set(clientId, scopes, granted, now) {
    for (const scope of scopes) {
      const existing = await this.db.get(
        'SELECT granted, gen FROM scope_grants WHERE client_id = ? AND scope = ?',
        [clientId, scope],
      );
      if (existing) {
        const isGranted = existing.granted === 1;
        if (isGranted === granted) continue; // 幂等：状态未翻转
        await this.db.run(
          `UPDATE scope_grants SET granted = ?, gen = ?, updated_at_ms = ?
           WHERE client_id = ? AND scope = ?`,
          [granted ? 1 : 0, existing.gen + 1, now, clientId, scope],
        );
      } else {
        // 没有记录：当前为隐式授权（gen 0）。撤销 => gen 1；授权 => 仍为 0，无需建记录
        if (!granted) {
          await this.db.run(
            `INSERT INTO scope_grants (client_id, scope, granted, gen, updated_at_ms)
             VALUES (?, ?, 0, 1, ?)`,
            [clientId, scope, now],
          );
        }
      }
    }
  }

  /**
   * 签发时调用：范围必须当前全部处于授权态，并返回固化的世代快照。
   * 必须在写事务内调用。
   * @returns {Promise<Record<string, number>>}
   */
  async snapshotForIssuance(clientId, scopes) {
    const rows = await this.db.all(
      `SELECT scope, granted, gen FROM scope_grants
       WHERE client_id = ? AND scope IN (${scopes.map(() => '?').join(', ')})`,
      [clientId, ...scopes],
    );
    const byScope = new Map(rows.map((r) => [r.scope, r]));
    const snapshot = {};
    for (const scope of scopes) {
      const row = byScope.get(scope);
      if (row && row.granted === 0) {
        throw new AuthError('invalid_scope', `范围 "${scope}" 已被撤销，不能签发`);
      }
      snapshot[scope] = row ? row.gen : 0;
    }
    return snapshot;
  }

  /**
   * 凭据使用时（兑换 / 刷新 / 校验）调用：用凭据签发时的世代快照过滤出
   * 当前仍有效的范围。某范围当前世代与快照不一致（被撤销或撤销后又重新授权）
   * 即从该凭据上剔除——旧凭据不能借重新授权恢复该范围。
   * 必须在写事务内调用（调用方持写锁时结果与后续写入原子一致）。
   * @returns {Promise<string[]>} 排序后的仍有效范围
   */
  async effectiveScopes(clientId, scopes, gensJson) {
    const snapshot = parseGens(gensJson, scopes);
    if (scopes.length === 0) return [];
    const rows = await this.db.all(
      `SELECT scope, granted, gen FROM scope_grants
       WHERE client_id = ? AND scope IN (${scopes.map(() => '?').join(', ')})`,
      [clientId, ...scopes],
    );
    const current = new Map(rows.map((r) => [r.scope, r]));
    return scopes.filter((scope) => {
      const row = current.get(scope);
      const currentGen = row ? row.gen : 0;
      return currentGen === snapshot[scope];
    });
  }
}

module.exports = { ScopeGrants, serializeGens, parseGens };
