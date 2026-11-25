# Smart Reverse Proxy

Dependency-free Node.js reverse proxy that intercepts requests, rewrites them,
and forwards anything unmatched to an upstream target.

## Run

```bash
cd "C:\Users\iyed\Documents\MY SERVER AUTH"
npm start
```

Node 18+. No `npm install` needed — only built-in modules (`http`, `https`,
`crypto`, `fs`, `path`).

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port (Render sets this automatically) |
| `HOST` | `0.0.0.0` | Bind address |
| `UPSTREAM_TARGET` | `https://iyed-j2uh.onrender.com` | Origin for unmatched paths |

## Local rules

| Method | Path | Behavior |
|---|---|---|
| GET | `/health` | Liveness + config summary |
| POST | `/api/verify`, `/api/verify/`, `/api/public/verify` | Returns license JSON locally |
| GET | `/api/public/key` | Returns public key text |
| POST | `/api/issue` | Issues a license record locally |

Everything else is forwarded to `UPSTREAM_TARGET` with the original method,
headers, and body.

## Editing rules

Rules live in the `RULES` array at the top of `server.js`. First match wins.
Each rule has:

- `name` — label used in the startup log
- `match` — regex tested against the incoming path
- `method` — optional method filter (`null` = any)
- `respond` — function returning `{ status, json|text|body, headers }` for a
  local response; when present, the request is never forwarded
- `rewrite` — optional `{ path, headers }` applied before forwarding

Example forwarding rule with a path rewrite:

```js
{
  name: 'legacy-login',
  match: /^\/login\/?$/,
  method: 'POST',
  rewrite: { path: '/api/verify' },
}
```

## Response rewriting

`forward()` copies upstream headers and body back to the client. To modify an
upstream response, edit the `upRes.on('end')` block in `forward()` — parse
`Buffer.concat(chunks)` as needed before calling `send()`.

## Notes

- Body limit: 2 MiB per request; larger requests get HTTP 413.
- Upstream timeout: 15 seconds; timeouts/errors return HTTP 502 with JSON.
- `UPSTREAM_TARGET` must be a full origin including scheme.
