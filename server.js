'use strict';

// License verification server.
// Endpoints:
//   POST /api/public/verify   - app-facing verification
//   GET  /health              - liveness
//   POST /api/issue           - issue a license (admin)
//   GET  /api/public/key      - public key for client-side verification

const express = require('express');
const crypto = require('crypto');
const config = require('./config');
const store = require('./store');
const license = require('./license');

const app = express();
app.use(express.json({ limit: '64kb' }));

function keys() {
  const k = store.getKeys();
  if (!k.publicKeyPem || !k.privateKeyPem) {
    throw new Error('Server keys missing. Run: npm run keygen');
  }
  return k;
}

// Admin bootstrap: install keys and licenses at runtime. Protected by a
// bearer token. Set ADMIN_TOKEN in the environment before deploying.
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
function adminGuard(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(403).json({ error: 'ADMIN_TOKEN not configured' });
  const h = req.headers['authorization'] || '';
  if (h !== 'Bearer ' + ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  next();
}

app.post('/admin/install', adminGuard, (req, res) => {
  const b = req.body || {};
  if (b.publicKeyPem && b.privateKeyPem) {
    store.saveKeys({
      publicKeyPem: b.publicKeyPem,
      privateKeyPem: b.privateKeyPem,
      createdAt: b.createdAt || new Date().toISOString(),
      algorithm: 'RSA-SHA256',
      modulusLength: 2048,
    });
  }
  if (b.licenses && typeof b.licenses === 'object') store.saveLicenses(b.licenses);
  res.json({ ok: true, keysInstalled: !!(b.publicKeyPem && b.privateKeyPem), licensesInstalled: !!b.licenses });
});

app.get('/health', (req, res) => {
  const k = store.getKeys();
  res.json({
    ok: true,
    time: new Date().toISOString(),
    name: config.licenseName,
    keysReady: !!(k.publicKeyPem && k.privateKeyPem),
  });
});

app.get('/api/public/key', (req, res) => {
  try {
    res.type('text/plain').send(keys().publicKeyPem);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// App-facing verification. Accepts the signed payload in several common
// shapes so it can be wired into different clients without changing the app.
// /api/verify is a short alias used by the patched Android DEX (fixed-length
// string patch): same handler, same response shape.
app.post(['/api/verify', '/api/verify/'], (req, res, next) => {
  req.url = config.verifyPath;
  next();
});
app.post(config.verifyPath, (req, res) => {
  let k;
  try { k = keys(); } catch (e) { return res.status(500).json({ error: e.message }); }

  const body = req.body || {};
  const auth = req.headers['authorization'] || '';
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  const token = body.token || body.license || body.payload || body.signed_payload ||
                body.data || bearer ||
                (req.headers['x-package-token'] && body.key
                  ? store.getLicenses()[body.key] && store.getLicenses()[body.key].signedPayload
                  : null);

  if (!token) {
    return res.status(200).json(license.responseFromClaims(
      { name: config.licenseName, version: config.appVersion, expires_at: new Date(0).toISOString() }, false));
  }

  // A raw issued key may arrive as the token; resolve it to its signed payload.
  const issued = store.getLicenses();
  if (issued[token] && issued[token].signedPayload) token = issued[token].signedPayload;

  const result = license.verify(token, k.publicKeyPem);
  if (!result.valid && !result.claims) {
    return res.status(200).json(license.responseFromClaims(
      { name: config.licenseName, version: config.appVersion, expires_at: new Date(0).toISOString() }, false));
  }
  const claims = result.claims || {
    name: config.licenseName, version: config.appVersion, expires_at: new Date(0).toISOString(),
  };
  res.status(200).json(license.responseFromClaims(claims, result.valid));
});

// Admin issuance. Protect with --admin-token in production via middleware.
app.post('/api/issue', (req, res) => {
  let k;
  try { k = keys(); } catch (e) { return res.status(500).json({ error: e.message }); }

  const b = req.body || {};
  const key = b.key || ('IYED-' + crypto.randomBytes(4).toString('hex').toUpperCase());
  const days = parseInt(b.days || String(config.defaultDays), 10);
  if (!Number.isFinite(days) || days <= 0) {
    return res.status(400).json({ error: 'days must be a positive integer' });
  }

  const record = license.issue({
    key,
    name: b.name || config.licenseName,
    days,
    hwid: b.hwid || '',
    deviceModel: b.device_model || '',
  }, k.privateKeyPem);

  const all = store.getLicenses();
  all[key] = record;
  store.saveLicenses(all);
  res.json(record);
});

app.listen(config.port, config.host, () => {
  console.log(`License server listening on http://${config.host}:${config.port}`);
  console.log(`Verify endpoint: POST ${config.verifyPath}`);
});
