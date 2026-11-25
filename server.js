'use strict';

// Minimal, dependency-free license verification server.
// No keys, no datastore, no crypto. Returns a valid-looking app response
// for every request on the verify paths. Built to never throw a 500.

const http = require('http');

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

function licenseBody() {
  return {
    status: 'success',
    success: true,
    valid: true,
    code: 200,
    message: 'OK',
    name: 'iyed',
    version: '7.0',
    days_left: 3650,
    seconds_left: 315360000,
    remaining_seconds: 315360000,
    expired_at: '2036-11-22T20:59:14Z',
    expires_at: '2036-11-22T20:59:14Z',
    expiration: '2036-11-22T20:59:14Z',
    expiry: '2036-11-22T20:59:14Z',
    expiration_date: '2036-11-22',
    expiry_date: '2036-11-22',
    expiredAt: '2036-11-22T20:59:14Z',
    expiresAt: '2036-11-22T20:59:14Z',
    verified: true,
    token: 'IYED-1234',
    server_time: Math.floor(Date.now() / 1000),
    data: {
      status: 'success',
      success: true,
      valid: true,
      name: 'iyed',
      version: '7.0',
      days_left: 3650,
      seconds_left: 315360000,
      remaining_seconds: 315360000,
      expired_at: '2036-11-22T20:59:14Z',
      expires_at: '2036-11-22T20:59:14Z',
      hwid: '',
      device_model: '',
      verified: true,
    },
  };
}

const server = http.createServer((req, res) => {
  const path = (req.url || '/').split('?')[0];

  if (path === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: true, name: 'iyed', time: new Date().toISOString() }));
    return;
  }

  if (path === '/api/public/key') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('IYED-1234');
    return;
  }

  // Every other path, any method: return the license response.
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(licenseBody()));
});

server.listen(PORT, HOST, () => {
  console.log('License server listening on ' + HOST + ':' + PORT);
});
