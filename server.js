'use strict';

// Smart reverse proxy.
//
// Intercepts incoming HTTP requests, inspects/rewrites them, and forwards to
// an upstream target. Responses can also be rewritten before being returned.
//
// Behavior:
//   - GET  /health                       -> liveness + config summary
//   - POST /api/verify, /api/verify/,
//          /api/public/verify            -> intercepted: license JSON returned
//                                           locally (no upstream call)
//   - POST /api/issue                    -> intercepted: issues a license record
//   - GET  /api/public/key               -> intercepted: public key text
//   - ALL  other paths                   -> forwarded to UPSTREAM_TARGET with
//                                           original method, headers, body
//
// Rules (edit RULES to add more):
//   match:    regex tested against the incoming path
//   method:   optional HTTP method filter (null = any)
//   rewrite:  optional { path, headers, body } applied before forwarding
//   respond:  optional static/local response { status, json|text|body, headers }
//
// No external dependencies: Node built-in http/https only.

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Upstream used for any path not matched by a local rule.
// Set UPSTREAM_TARGET to a full origin, e.g. https://api.example.com
const UPSTREAM_TARGET = process.env.UPSTREAM_TARGET || 'https://iyed-j2uh.onrender.com';

const LICENSE = {
  status: 'success', success: true, valid: true, code: 200, message: 'OK',
  name: 'iyed', version: '7.0',
  days_left: 3650, seconds_left: 315360000, remaining_seconds: 315360000,
  expired_at: '2036-11-22T20:59:14Z', expires_at: '2036-11-22T20:59:14Z',
  expiration: '2036-11-22T20:59:14Z', expiry: '2036-11-22T20:59:14Z',
  expiration_date: '2036-11-22', expiry_date: '2036-11-22',
  expiredAt: '2036-11-22T20:59:14Z', expiresAt: '2036-11-22T20:59:14Z',
  verified: true, token: 'IYED-1234',
  data: {
    status: 'success', success: true, valid: true,
    name: 'iyed', version: '7.0', days_left: 3650,
    seconds_left: 315360000, remaining_seconds: 315360000,
    expired_at: '2036-11-22T20:59:14Z', expires_at: '2036-11-22T20:59:14Z',
    hwid: '', device_model: '', verified: true,
  },
};

const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5uSni2mOFBo02/TiT8C4\n' +
  'mT2d4C1HB7jEnekU25ouM2liQIi6fFyj0o8hB11y3Ra4kyKUqs4SsT7yRAT8YiK2\n' +
  '8vunQVuefhH8nz6laagSfZStY/l+NcxqoU4XAVm5CiowE0khXIdp+/exImDKr6RR\n' +
  'n+MFoVPq6N2S2ceGis4jkqVBI9QNwVzV0L4QkenhhSkdltjNCxxExvfSul/zLtbk\n' +
  'J480xG31ZsQwGsGotrNWoCyP+JFyiCI/aL///ZuXDuDN7FAM/8WETFYK4LMZoW+6\n' +
  'npgfN3gbrAF5eRgnlmIWveADzQBYUydPQi230mhRGA0FBIfiLaq7N4BAE4tWyq6K\n' +
  '/wIDAQAB\n-----END PUBLIC KEY-----\n';

// ---------------------------------------------------------------------------
// Rule table — order matters, first match wins
// ---------------------------------------------------------------------------
const RULES = [
  {
    name: 'health',
    match: /^\/health\/?$/,
    method: 'GET',
    respond: () => ({
      status: 200,
      json: { ok: true, name: 'iyed', proxy: true, upstream: UPSTREAM_TARGET, time: new Date().toISOString() },
    }),
  },
  {
    name: 'verify',
    match: /^\/api\/(public\/)?verify\/?$/,
    method: null,
    respond: () => ({ status: 200, json: LICENSE }),
  },
  {
    name: 'public-key',
    match: /^\/api\/public\/key\/?$/,
    method: 'GET',
    respond: () => ({ status: 200, text: PUBLIC_KEY, contentType: 'text/plain; charset=utf-8' }),
  },
  {
    name: 'issue',
    match: /^\/api\/issue\/?$/,
    method: 'POST',
    respond: (req, bodyBuf) => {
      let input = {};
      try { input = JSON.parse(bodyBuf.toString('utf8') || '{}'); } catch (_) { input = {}; }
      const key = input.key || ('IYED-' + crypto.randomBytes(4).toString('hex').toUpperCase());
      const days = Number.isFinite(+input.days) && +input.days > 0 ? +input.days : 3650;
      const expires = new Date(Date.now() + days * 86400000).toISOString();
      return {
        status: 200,
        json: {
          key,
          claims: { key, name: input.name || 'iyed', version: '7.0', days_left: days, expires_at: expires },
          signedPayload: 'IYED-1234',
          issuedAt: new Date().toISOString(),
          expiresAt: expires,
        },
      };
    },
  },
  // Example of a forwarding rule with a path rewrite:
  // {
  //   name: 'legacy-login',
  //   match: /^\/login\/?$/,
  //   method: 'POST',
  //   rewrite: { path: '/api/verify' },
  // },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function send(res, status, payload, contentType, extraHeaders) {
  const headers = Object.assign({
    'Content-Type': contentType || 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  }, extraHeaders || {});
  if (Buffer.isBuffer(payload)) {
    headers['Content-Length'] = payload.length;
  } else {
    const b = Buffer.from(payload, 'utf8');
    headers['Content-Length'] = b.length;
    payload = b;
  }
  res.writeHead(status, headers);
  res.end(payload);
}

function localResponse(res, spec) {
  const status = spec.status || 200;
  if (spec.json !== undefined) {
    send(res, status, JSON.stringify(spec.json), 'application/json; charset=utf-8', spec.headers);
  } else if (spec.text !== undefined) {
    send(res, status, spec.text, spec.contentType || 'text/plain; charset=utf-8', spec.headers);
  } else if (spec.body !== undefined) {
    send(res, status, spec.body, spec.contentType || 'application/octet-stream', spec.headers);
  } else {
    send(res, status, '', 'text/plain; charset=utf-8', spec.headers);
  }
}

function readBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > (limitBytes || 2 * 1024 * 1024)) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function forward(req, res, bodyBuf, rule) {
  let target;
  try {
    target = new URL(UPSTREAM_TARGET);
  } catch (e) {
    return send(res, 500, JSON.stringify({ error: 'bad UPSTREAM_TARGET: ' + e.message }));
  }

  const rewrite = (rule && rule.rewrite) || {};
  const outgoingPath = rewrite.path || req.url;
  const headers = Object.assign({}, req.headers, rewrite.headers || {});
  headers.host = target.host;
  delete headers['content-length'];

  const opts = {
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || (target.protocol === 'https:' ? 443 : 80),
    method: req.method,
    path: outgoingPath,
    headers,
    timeout: 15000,
  };

  const transport = target.protocol === 'https:' ? https : http;
  const up = transport.request(opts, (upRes) => {
    const chunks = [];
    upRes.on('data', (c) => chunks.push(c));
    upRes.on('end', () => {
      const out = Buffer.concat(chunks);
      const respHeaders = Object.assign({}, upRes.headers);
      delete respHeaders['content-length'];
      delete respHeaders['transfer-encoding'];
      send(res, upRes.statusCode || 502, out,
        respHeaders['content-type'] || 'application/octet-stream', respHeaders);
    });
  });
  up.on('timeout', () => up.destroy(new Error('upstream timeout')));
  up.on('error', (e) => {
    if (!res.headersSent) {
      send(res, 502, JSON.stringify({ error: 'upstream error: ' + e.message, upstream: UPSTREAM_TARGET }));
    }
  });
  if (bodyBuf && bodyBuf.length) up.write(bodyBuf);
  up.end();
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const urlPath = (req.url || '/').split('?')[0];
  let bodyBuf = Buffer.alloc(0);
  try {
    bodyBuf = await readBody(req);
  } catch (e) {
    return send(res, 413, JSON.stringify({ error: e.message }));
  }

  for (const rule of RULES) {
    if (!rule.match.test(urlPath)) continue;
    if (rule.method && rule.method !== req.method) continue;
    if (rule.respond) {
      try {
        return localResponse(res, rule.respond(req, bodyBuf));
      } catch (e) {
        return send(res, 500, JSON.stringify({ error: 'rule ' + rule.name + ': ' + e.message }));
      }
    }
    return forward(req, res, bodyBuf, rule);
  }

  // No local rule matched — transparent reverse proxy to upstream.
  forward(req, res, bodyBuf, null);
});

server.listen(PORT, HOST, () => {
  console.log(`Smart reverse proxy listening on http://${HOST}:${PORT}`);
  console.log(`Upstream: ${UPSTREAM_TARGET}`);
  console.log(`Local rules: ${RULES.map((r) => r.name).join(', ')}`);
});
