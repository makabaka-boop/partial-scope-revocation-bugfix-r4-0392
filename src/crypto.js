'use strict';

const { randomBytes, createHash, timingSafeEqual } = require('node:crypto');

/** 生成不透明随机串（授权码 / 访问令牌 / 刷新令牌），URL-safe Base64。 */
function generateOpaque(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

/**
 * 计算令牌/授权码的 SHA-256 摘要（hex）。
 * 数据库只保存摘要，原始值仅在签发响应中出现一次。
 */
function sha256(value, encoding = 'hex') {
  return createHash('sha256').update(value).digest(encoding);
}

/** 令牌摘要（令牌本身已是高熵随机串，仍只存摘要，库文件泄露不暴露令牌）。 */
function hashToken(token) {
  return sha256(token);
}

/** 生成 PKCE code_verifier（RFC 7636：43~128 字符的 unreserved 串）。 */
function generateCodeVerifier() {
  return randomBytes(32).toString('base64url');
}

/**
 * 计算 PKCE code_challenge。
 * @param {string} verifier
 * @param {'S256'|'plain'} method
 */
function computeCodeChallenge(verifier, method = 'S256') {
  if (method === 'plain') return verifier;
  if (method !== 'S256') {
    throw new Error(`不支持的 code_challenge_method: ${method}`);
  }
  return sha256(verifier, 'base64url');
}

/** 常量时间字符串比较，避免时序侧信道。 */
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

module.exports = {
  generateOpaque,
  sha256,
  hashToken,
  generateCodeVerifier,
  computeCodeChallenge,
  safeEqual,
};
