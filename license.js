'use strict';

// License issuance, signing, verification, and response construction.
// The response shape matches the fields the iOS app reads from /api/public/verify.

const crypto = require('crypto');
const config = require('./config');

const DAY_MS = 24 * 60 * 60 * 1000;

function iso(ms) { return new Date(ms).toISOString(); }

// Build the unsigned license claims object.
function buildClaims({ key, name, days, hwid, deviceModel }) {
  const now = Date.now();
  const expires = now + days * DAY_MS;
  return {
    key,
    name: name || config.licenseName,
    version: config.appVersion,
    package_id: config.packageId,
    issued_at: iso(now),
    expires_at: iso(expires),
    days_left: days,
    seconds_left: Math.floor(days * 86400),
    hwid: hwid || '',
    device_model: deviceModel || '',
    status: 'success',
  };
}

// Canonical serialization: sorted keys, no whitespace. Signing and verifying
// must use exactly the same bytes.
function canonical(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function sign(claims, privateKeyPem) {
  const data = canonical(claims);
  const signature = crypto.sign('sha256', Buffer.from(data), privateKeyPem).toString('base64');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `${payload}.${signature}`;
}

function verify(signedPayload, publicKeyPem) {
  if (typeof signedPayload !== 'string') return { valid: false, reason: 'not a string' };
  const parts = signedPayload.split('.');
  if (parts.length !== 2) return { valid: false, reason: 'malformed payload' };
  let claims, signature;
  try {
    claims = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    signature = Buffer.from(parts[1], 'base64');
  } catch (e) {
    return { valid: false, reason: 'decode failed: ' + e.message };
  }
  const data = canonical(claims);
  let ok;
  try {
    ok = crypto.verify('sha256', Buffer.from(data), publicKeyPem, signature);
  } catch (e) {
    return { valid: false, reason: 'verify failed: ' + e.message };
  }
  if (!ok) return { valid: false, reason: 'bad signature' };
  if (Date.now() > Date.parse(claims.expires_at)) return { valid: false, reason: 'expired', claims };
  return { valid: true, claims };
}

function issue(params, privateKeyPem) {
  const claims = buildClaims(params);
  const signedPayload = sign(claims, privateKeyPem);
  return {
    key: claims.key,
    claims,
    signedPayload,
    issuedAt: claims.issued_at,
    expiresAt: claims.expires_at,
  };
}

// Build the JSON object returned by the verification endpoint. Every field
// the app reads is present at top level and under data.
function responseFromClaims(claims, valid) {
  const now = Date.now();
  const expires = Date.parse(claims.expires_at);
  const remainingMs = Math.max(0, expires - now);
  const daysLeft = Math.floor(remainingMs / DAY_MS);
  const secondsLeft = Math.floor(remainingMs / 1000);
  const expiredAt = claims.expires_at;

  const base = {
    status: valid ? 'success' : 'error',
    success: !!valid,
    valid: !!valid,
    code: valid ? 200 : 403,
    message: valid ? config.responseMessage : 'invalid or expired license',
    name: claims.name,
    version: claims.version,
    days_left: daysLeft,
    seconds_left: secondsLeft,
    remaining_seconds: secondsLeft,
    expired_at: expiredAt,
    expires_at: expiredAt,
    expiration: expiredAt,
    expiry: expiredAt,
    expiration_date: expiredAt.slice(0, 10),
    expiry_date: expiredAt.slice(0, 10),
    expiredAt,
    expiresAt: expiredAt,
    verified: !!valid,
    server_time: Math.floor(now / 1000),
  };

  base.data = {
    status: base.status,
    success: !!valid,
    valid: !!valid,
    name: claims.name,
    version: claims.version,
    days_left: daysLeft,
    seconds_left: secondsLeft,
    remaining_seconds: secondsLeft,
    expired_at: expiredAt,
    expires_at: expiredAt,
    hwid: claims.hwid,
    device_model: claims.device_model,
    verified: !!valid,
  };
  return base;
}

module.exports = { buildClaims, canonical, sign, verify, issue, responseFromClaims, DAY_MS };
