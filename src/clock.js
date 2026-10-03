'use strict';

/**
 * 可注入时钟。
 * 服务内所有到期判断（授权码、访问令牌、刷新令牌）一律经过 clock.now()，
 * 生产环境用系统时钟，测试用可控时钟直接推进时间，不依赖真实等待。
 */
class Clock {
  /** @returns {number} Unix 毫秒时间戳 */
  now() {
    return Date.now();
  }
}

/** 测试用可控时钟：初始时间可指定，tick 毫秒推进。 */
class FakeClock extends Clock {
  /**
   * @param {number} [initialMs] 初始 Unix 毫秒时间戳
   */
  constructor(initialMs = 1_700_000_000_000) {
    super();
    this._now = initialMs;
  }

  now() {
    return this._now;
  }

  /** @param {number} ms 向前推进的毫秒数 */
  tick(ms) {
    this._now += ms;
  }

  /** 直接设置当前时间 */
  set(ms) {
    this._now = ms;
  }
}

module.exports = { Clock, FakeClock };
