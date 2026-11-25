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

app.get('/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString(), name: config.licenseName });
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
app.post(config.verifyPath, (req, res) => {
  let k;
  try { k = keys(); } catch (e) { return res.status(500).json({ error: e.message }); }

  const body = req.body || {};
  const token = body.token || body.license || body.payload || body.signed_payload ||
                body.data || (req.headers['x-package-token'] && body.key
                  ? store.getLicenses()[body.key] && store.getLicenses()[body.key].signedPayload
                  : null);

  if (!token) {
    return res.status(200).json(license.responseFromClaims(
      { name: config.licenseName, version: config.appVersion, expires_at: new Date(0).toISOString() }, false));
  }

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
