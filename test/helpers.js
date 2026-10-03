'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { AuthService } = require('../src/server');
const { FakeClock } = require('../src/clock');

const TMP_DIR = path.join(os.tmpdir(), `authsvc-tests-${process.pid}`);
fs.mkdirSync(TMP_DIR, { recursive: true });

let counter = 0;
function tempDbPath() {
  counter += 1;
  return path.join(TMP_DIR, `test-${Date.now()}-${counter}.db`);
}

function cleanupTemp() {
  try {
    for (const f of fs.readdirSync(TMP_DIR)) {
      try {
        fs.rmSync(path.join(TMP_DIR, f), { force: true });
      } catch {
        /* ignore */
      }
    }
    fs.rmdirSync(TMP_DIR);
  } catch {
    /* ignore */
  }
}

const CLIENT_A = {
  clientId: 'client-a',
  name: '客户端 A',
  redirectUris: ['http://client-a.example/cb'],
  scopes: ['read:profile', 'read:docs'],
};

const CLIENT_B = {
  clientId: 'client-b',
  name: '客户端 B',
  redirectUris: ['http://client-b.example/cb'],
  scopes: ['read:profile', 'write:docs'],
};

/**
 * 构造一个已登记两个客户端的服务（临时文件 + 可控时钟）。
 * 返回 { service, clock, dbPath }。
 */
async function makeService(opts = {}) {
  const dbPath = opts.dbPath || tempDbPath();
  const clock = opts.clock || new FakeClock();
  const service = new AuthService({
    db: dbPath,
    clock,
    ttls: opts.ttls,
    hooks: opts.hooks,
  });
  if (opts.register !== false) {
    await service.registerClient(CLIENT_A);
    await service.registerClient(CLIENT_B);
  }
  return { service, clock, dbPath, close: () => service.close() };
}

/** 在同一数据库文件上再开一个服务实例（模拟多实例 / 重启）。 */
function openAnotherService(dbPath, clock, opts = {}) {
  const service = new AuthService({
    db: dbPath,
    clock: clock || new FakeClock(),
    ttls: opts.ttls,
    hooks: opts.hooks,
  });
  return service;
}

/**
 * 确定性并发闩：
 *   const g = new Gate();
 *   g.enter()        // 进入临界区前调用（计数+1）
 *   await g.waitFor(n) // 等待 n 个参与者都已 enter
 *   g.open()         // 放行全部
 *
 * enter 时若 gate 已 open 则立即继续（不阻塞）。
 */
class Gate {
  constructor() {
    this.count = 0;
    this.opened = false;
    this._waiters = [];
    this._openListeners = null;
    this._openPromise = new Promise((resolve) => {
      this._openListeners = resolve;
    });
  }

  async enter() {
    this.count += 1;
    const w = this._waiters.shift();
    if (w) w();
    if (this.opened) return;
    await this._openPromise;
  }

  /** 等待直到 count 达到 n（参与者已经走到闩前）。 */
  async waitFor(n, timeoutMs = 2000) {
    if (this.count >= n) return;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Gate.waitFor 超时')), timeoutMs);
      const check = () => {
        if (this.count >= n) {
          clearTimeout(timer);
          resolve();
        } else {
          this._waiters.push(() => {
            clearTimeout(timer);
            check();
          });
        }
      };
      check();
    });
  }

  open() {
    this.opened = true;
    this._openListeners();
  }
}

async function settle(promise) {
  try {
    return { ok: true, value: await promise };
  } catch (e) {
    return { ok: false, error: e };
  }
}

module.exports = {
  TMP_DIR,
  tempDbPath,
  cleanupTemp,
  CLIENT_A,
  CLIENT_B,
  makeService,
  openAnotherService,
  Gate,
  settle,
};
