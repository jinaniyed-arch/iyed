# License Auth Server

Server for issuing and verifying signed licenses. Built for the `iyed` license
with adjustable duration and a response shape matching the fields the iOS app
reads from `/api/public/verify`.

## Layout

```
config.js              all adjustable values (host, port, name, days, paths)
license.js             issue / sign / verify / build response
store.js               JSON persistence (keys.json, licenses.json)
server.js              Express server + endpoints
tools/keygen.js        RSA keypair generator
tools/issue.js         license issuance CLI
tools/verify-client.js client-side verification helper
```

## Setup

```bash
cd "C:\Users\iyed\Documents\MY SERVER AUTH"
npm install
npm run keygen
npm start
```

No keys and no licenses ship in the repo. `keys.json` and `licenses.json` are
created on first use and hold the private key and issued records — keep them
out of version control.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness |
| GET | `/api/public/key` | PEM public key for client verification |
| POST | `/api/public/verify` | app-facing verification; returns the full app response |
| POST | `/api/issue` | issue a new signed license |

## Issue a license

CLI:

```bash
npm run issue -- --key IYED-1234 --name iyed --days 3650 --hwid ABCDEF --device iPhone16,2
```

HTTP:

```bash
curl -X POST http://localhost:3000/api/issue \
  -H "Content-Type: application/json" \
  -d '{"key":"IYED-1234","days":3650,"hwid":"ABCDEF"}'
```

`--days` sets the duration from the moment of issuance. `days_left`,
`seconds_left`, `expired_at` and every related field are computed from it on
every verification response, so the countdown updates live.

## Verify

```bash
curl -X POST http://localhost:3000/api/public/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"<signedPayload>"}'
```

The server also accepts `license`, `payload`, `signed_payload`, or `data` as the
token field. A valid license returns HTTP 200 with `status:"success"`,
`success:true`, `days_left`, `expired_at`, and the full nested `data` block.
An invalid or expired license returns HTTP 200 with `status:"error"` and
`success:false` — the app sees a well-formed response either way.

Client-side check without contacting the server:

```bash
npm run verify -- <signedPayload>
```

## Pointing the app at this server

The app binary calls `https://mygold.squareweb.app/api/public/verify`. To use
this server, either change that URL in the app or route the domain to this
server with TLS terminated in front of it. The response shape is already built
to match the fields the app reads.

## Configuration

Edit `config.js`:

- `host`, `port` — bind address
- `verifyPath` — app-facing verification path
- `licenseName` — default owner name (`iyed`)
- `defaultDays` — default duration (3650)
- `packageId`, `packageToken` — copied from the app binary
- `rsaModulusLength` — signing key size

## Notes

- Node 18+, Express 4.x.
- Signing: RSA-SHA256 over canonical JSON (sorted keys); payload is
  `base64url(claims).base64(signature)`.
- `npm run keygen -- --force` regenerates keys and invalidates every issued
  license.
- Failure modes: missing keys → 500 with a clear message; malformed token →
  error response; expired license → `success:false` with `days_left:0`.
