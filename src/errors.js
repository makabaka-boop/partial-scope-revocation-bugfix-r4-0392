'use strict';

/**
 * 授权服务错误。
 * error 字段对应 OAuth 2.0 的错误码，便于映射为
 * application/x-www-form-urlencoded / JSON 错误响应。
 */
class AuthError extends Error {
  /**
   * @param {string} error OAuth 风格错误码，如 invalid_grant / invalid_scope / invalid_client
   * @param {string} [message]
   * @param {number} [status] 建议的 HTTP 状态码
   * @param {object} [opts]
   * @param {boolean} [opts.commitAfterThrow=false]
   *        为 true 时，事务封装会先 COMMIT 再把错误抛出。
   *        用于“检测到重放 => 已在同一事务内撤销家族，随后还要向客户端报错”的场景：
   *        撤销必须持久化，不能随异常一起回滚。
   */
  constructor(error, message, status = 400, opts = {}) {
    super(message || error);
    this.name = 'AuthError';
    this.error = error;
    this.status = status;
    this.commitAfterThrow = opts.commitAfterThrow === true;
  }
}

module.exports = { AuthError };
