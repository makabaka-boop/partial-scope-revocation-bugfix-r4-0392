'use strict';

const { Database: SQLiteDatabase } = require('node-sqlite3-wasm');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * 简单异步互斥锁。
 *
 * 同一连接上的写事务先经互斥锁串行化，保证“验证 + 写入”在本实例内不交错；
 * 跨实例/跨进程的原子性由 BEGIN IMMEDIATE 写锁 + 条件 UPDATE 在数据库层兜底。
 */
class Mutex {
  constructor() {
    /** @type {Promise<void>} */
    this._tail = Promise.resolve();
  }

  /**
   * @template T
   * @param {() => Promise<T>|T} fn
   * @returns {Promise<T>}
   */
  runExclusive(fn) {
    const previous = this._tail;
    let release;
    this._tail = new Promise((resolve) => {
      release = resolve;
    });
    return (async () => {
      await previous;
      try {
        return await fn();
      } finally {
        release();
      }
    })();
  }
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS clients (
  client_id    TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS client_redirect_uris (
  client_id    TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS client_scopes (
  client_id TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
  scope     TEXT NOT NULL,
  PRIMARY KEY (client_id, scope)
);

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash             TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL REFERENCES clients(client_id),
  redirect_uri          TEXT NOT NULL,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  scope                 TEXT NOT NULL,
  expires_at_ms         INTEGER NOT NULL,
  redeemed_at_ms        INTEGER,
  created_at_ms         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS token_families (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id     TEXT NOT NULL REFERENCES clients(client_id),
  scope         TEXT NOT NULL,
  revoked_at_ms INTEGER,
  revoke_reason TEXT,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash                      TEXT PRIMARY KEY,
  family_id                       INTEGER NOT NULL REFERENCES token_families(id),
  expires_at_ms                   INTEGER NOT NULL,
  consumed_at_ms                  INTEGER,
  superseded_by_family_token_hash TEXT,
  created_at_ms                   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash    TEXT PRIMARY KEY,
  family_id     INTEGER NOT NULL REFERENCES token_families(id),
  scope         TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_access_family  ON access_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_codes_expiry   ON auth_codes(expires_at_ms);
`;

/**
 * SQLite 连接封装。
 *
 * 针对 node-sqlite3-wasm 的两个与原生 better-sqlite3 不同的行为做了收口：
 *
 * 1. 绑定参数必须以“单个值或单个数组”传入（.run([a,b])）；展开传参只会绑定第一个值。
 * 2. 该 WASM VFS 在另一连接持有写事务（rollback journal）期间，对任何语句
 *    （包括 SELECT，甚至 BEGIN IMMEDIATE）都会立刻抛出 "database is locked"，
 *    没有原生 SQLite 的 busy_handler 阻塞语义。因此所有语句访问都要
 *    “让出事件循环 -> 重试”，等待持锁事务提交。
 *
 * 其它保证：
 * - run/get/all 走驱动便捷方法（每条语句执行后自动 finalize），避免残留读锁；
 * - withImmediateTx 先取 RESERVED 写锁再执行业务；
 * - 状态全部落盘，重启后授权码/令牌状态不丢失、不复活。
 */
class Db {
  /**
   * @param {string} path 数据库文件路径（或 ':memory:'）
   * @param {object} [opts]
   * @param {number} [opts.busyTimeoutMs=5000] 锁冲突忙等待总预算（真实计时器，与业务时钟无关）
   * @param {number} [opts.busyRetryDelayMs=5] 每次重试前让出事件循环的毫秒数
   */
  constructor(path, { busyTimeoutMs = 5000, busyRetryDelayMs = 5 } = {}) {
    this.path = path;
    this.busyRetryDelayMs = busyRetryDelayMs;
    this.busyMaxAttempts = Math.max(1, Math.ceil(busyTimeoutMs / busyRetryDelayMs));
    /** 统计因锁冲突发生的重试次数（便于测试观察） */
    this.busyRetries = 0;
    this.mutex = new Mutex();
    this._db = new SQLiteDatabase(path);
    this._db.exec('PRAGMA foreign_keys=ON');
  }

  /**
   * 预编译语句（驱动原生 Statement）。
   *
   * 警告：node-sqlite3-wasm 的 Statement 不会自动 finalize，未显式 finalize
   * 会残留 SHARED 读锁。业务代码请优先使用 run/get/all；
   * 只有在断言/维护脚本等确需复用语句时才用本方法，并自行 finalize。
   */
  prepare(sql) {
    return this._db.prepare(sql);
  }

  /** 无绑定参数的多语句执行（DDL / BEGIN / COMMIT），同步。 */
  exec(sql) {
    return this._db.exec(sql);
  }

  /**
   * 写语句，返回 { changes, lastInsertRowid }。
   * @returns {Promise<{changes:number, lastInsertRowid:number|bigint}>}
   */
  run(sql, params = []) {
    const values = Array.isArray(params) ? params : [params];
    return this._withBusyRetry(() => this._db.run(sql, values));
  }

  /** 查询单行；无结果返回 null。 */
  get(sql, params = []) {
    const values = Array.isArray(params) ? params : [params];
    return this._withBusyRetry(() => this._db.get(sql, values));
  }

  /** 查询多行。 */
  all(sql, params = []) {
    const values = Array.isArray(params) ? params : [params];
    return this._withBusyRetry(() => this._db.all(sql, values));
  }

  /**
   * 语句级忙等待：遇 SQLITE_BUSY 让出事件循环后重试整个语句，
   * 直到超过 busyTimeoutMs 预算。必须让出事件循环——同步忙等会饿死
   * 持锁事务（它需要事件循环才能走到 COMMIT）。
   */
  async _withBusyRetry(action) {
    let attempt = 0;
    for (;;) {
      try {
        return action();
      } catch (e) {
        if (this._isBusy(e) && attempt < this.busyMaxAttempts) {
          attempt += 1;
          this.busyRetries += 1;
          await sleep(this.busyRetryDelayMs);
          continue;
        }
        throw e;
      }
    }
  }

  isOpen() {
    return this._db.isOpen;
  }

  close() {
    if (this._db.isOpen) this._db.close();
  }

  /**
   * 在 BEGIN IMMEDIATE 事务中执行 fn（可异步）。
   *
   * 锁冲突时让出事件循环并整事务重试；一旦拿到写锁，
   * “条件 UPDATE 消费一次性凭据”即为原子操作，不会双重消费。
   *
   * @template T
   * @param {() => Promise<T>|T} fn
   * @returns {Promise<T>}
   */
  withImmediateTx(fn) {
    return this.mutex.runExclusive(() => this._txWithBusyRetry(fn));
  }

  async _txWithBusyRetry(fn) {
    let attempt = 0;
    for (;;) {
      try {
        this._db.exec('BEGIN IMMEDIATE');
      } catch (e) {
        if (this._isBusy(e) && attempt < this.busyMaxAttempts) {
          attempt += 1;
          this.busyRetries += 1;
          await sleep(this.busyRetryDelayMs);
          continue;
        }
        throw e;
      }

      try {
        const result = await fn();
        this._db.exec('COMMIT');
        return result;
      } catch (e) {
        if (e && e.commitAfterThrow === true) {
          // 业务在事务内完成了必须持久化的写入（如重放触发的家族撤销），
          // 先提交，再把错误继续抛给调用方。
          this._db.exec('COMMIT');
        } else {
          try {
            this._db.exec('ROLLBACK');
          } catch {
            /* 连接异常时 ROLLBACK 可能失败，忽略二次异常 */
          }
        }
        throw e;
      }
    }
  }

  _isBusy(e) {
    return e && typeof e.message === 'string' && /database is locked/i.test(e.message);
  }
}

/** 幂等建表（重启 / 多实例启动时安全）。仅应在无其他连接竞争时执行。 */
function migrate(db) {
  db.exec(SCHEMA_SQL);
}

module.exports = { Db, Mutex, migrate, SCHEMA_SQL };
