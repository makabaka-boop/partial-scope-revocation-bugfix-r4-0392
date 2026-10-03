const { AuthError } = require("./errors");
class ScopeGrants {
  constructor(db) {
    this.db = db;
    this.revoked = new Set();
  }
  async set(clientId, scopes, granted) {
    for (const scope of scopes)
      if (granted) this.revoked.delete(scope);
      else this.revoked.add(scope);
  }
  async authorize(clientId, scopes) {
    if (scopes.some((scope) => this.revoked.has(scope)))
      throw new AuthError("invalid_scope", "范围已被撤销");
    return scopes;
  }
}
module.exports = { ScopeGrants };
