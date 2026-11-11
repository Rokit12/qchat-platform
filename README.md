# QChat: username‑only messenger with post‑quantum end‑to‑end encryption

A WhatsApp‑style messenger where people find each other **only by username**. There's no phone number, no email and no password. Messages, files, voice notes, statuses and **calls** are end‑to‑end encrypted with NIST post‑quantum cryptography: a PQ double ratchet built on ML‑KEM‑768 + ML‑DSA‑65. See [`PROTOCOL.md`](PROTOCOL.md) for the full spec and threat model.

## Features

- **Messaging:** 1:1 chats and **groups of up to 3,500 members** (sender keys: each message is encrypted once and stays the same size however big the group is; add members by pasting a list of usernames), replies, reactions, edit, delete for everyone, forward, in‑chat search, disappearing messages, ticks (sent / delivered / read), typing and "recording audio" indicators, online / last seen.
- **Media:** photos, videos, files up to 10 MB, voice notes, drag‑and‑drop and paste.
- **Calls:** 1:1 and **group** voice/video calls with up to 8 people. Every audio/video frame is encrypted with keys exchanged over the PQ ratchet.
- **Status:** 24‑hour text or photo stories, shared with your contacts, with view receipts and replies.
- **Go Live (in Status):** stream your phone camera to your contacts, with a front/back camera flip and mic mute. Viewers' comments pop up over the video for everyone, and viewers can tap or double‑tap to send floating hearts. Video frames, the title and comments are end‑to‑end encrypted with post‑quantum keys. Up to 20 viewers at once.
- **Share my link:** every user gets `https://your-domain/@username` plus a QR code (🔗 button). Anyone who opens it signs up or logs in and lands straight in a chat with you.
- **Multi‑device:** up to 5 devices per account. Messages fan out to every device, sent messages sync between them, history can be copied to a new device, and any device can be removed remotely.
- **Security:**
  - Forward secrecy and post‑compromise security.
  - Signed one‑time prekeys.
  - Safety numbers and "verified" contacts, with warnings when a contact's key changes.
  - Alerts when a new device is linked to your account.
  - Encrypted local database, with an optional **passcode lock** (Argon2id) and auto‑lock.
  - **Log out without losing anything:** chats stay on the device (locked) and in an automatic **end‑to‑end encrypted backup** on the server, so they come back when you log in again — on the same device or a new one. Only *Delete account* erases them.
  - **Encrypted backups** you can also export and import yourself.
- **PIN login:** log in on any device with your username and a 6‑digit PIN you set at sign‑up. Your recovery key is only needed if you forget your PIN.
- **Admin dashboard** (`/admin`, sign‑in with email + password + authenticator app):
  - Every user with their activity timeline.
  - User management: suspend, force sign‑out, remove devices, reset PIN, delete.
  - Analytics: sign‑ups, daily active users, message volume, logins, platforms, security.
  - Security events, IP bans, an audit log and admin roles.
- **Service status:** live up/down monitoring of every component, with uptime history and outage incidents, on the admin home page, a public `/status` page and the app's home screen.
- **Hardened against attacks** (details in [SECURITY.md](SECURITY.md)):
  - On‑device phishing detection with a safety screen before any link opens, warnings for unknown contacts and scam messages, a guard against sending your recovery key, and flags for dangerous files.
  - Impersonation blocking.
  - Intrusion detection with account‑takeover alerts, automatic lockouts and IP bans, plus an admin security dashboard.
  - Rate limits and proof‑of‑work against spam and DDoS.
  - Strict HTTPS, HSTS and CSP, a WebSocket origin check, and strict key‑change mode against man‑in‑the‑middle attacks.
- **Notifications:** in‑app notifications, plus **Web Push when the app is closed**. Push messages carry no content, only who it's from.
- **Scale:** SQLite out of the box, or **Postgres + Redis** to run as many server instances as you need behind a load balancer.
- **App:** installable as a PWA, works on mobile layouts, loads offline.

## Quick start

```bash
npm install
npm start               # builds the client, serves http://localhost:3000 (SQLite in ./data)
```

Requires Node 22.5 or newer. Open two browser profiles, create two usernames, and message one from the other.

For the admin dashboard, start the server with `ADMIN_BOOTSTRAP_USER` and `ADMIN_BOOTSTRAP_PASSWORD` set (or run `npm run admin -- create you@example.com --role owner`), then open http://localhost:3000/admin.

## Production

```bash
cp .env.example .env    # set DOMAIN, TURN_SECRET, POSTGRES_PASSWORD
docker compose up -d    # Caddy (automatic HTTPS) → 2× QChat → Postgres + Redis, plus coturn for calls
```

The compose file runs two app instances to show horizontal scaling. Add more by duplicating the service.

| Variable | Purpose |
|---|---|
| `PORT` | HTTP/WebSocket port (default 3000) |
| `DATA_DIR` | SQLite location, used when `DATABASE_URL` is not set |
| `DATABASE_URL` | Postgres (`postgres://…`) for multi‑instance deployments |
| `REDIS_URL` | Cross‑instance delivery and presence |
| `TURN_URL`, `TURN_SECRET` | coturn with `use-auth-secret`. Short‑lived TURN credentials are minted per user and never put in the page. |
| `STUN_URLS` | Override the STUN servers |
| `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT` | Web Push keys. If unset, they're generated once and stored in the database. |
| `ADMIN_BOOTSTRAP_USER`, `ADMIN_BOOTSTRAP_PASSWORD` | First owner admin, created on first start only if no admin exists yet; 2FA is set up at first sign‑in at `/admin`. Put them in `.env`, never in the repo, and use **Change password** in the dashboard after your first sign‑in. |
| `ADMIN_DATABASE_URL` | Separate Postgres for admin data and analytics (SQLite `admin.db` if unset) |
| `ADMIN_SECRET_KEY`, `PIN_PEPPER` | Keys kept outside the databases: they encrypt admin 2FA secrets and pepper the PIN‑login checks |
| `ADMIN_IPS` | Only allow the admin dashboard from these IPs |
| `SECURITY_WEBHOOK_URL` | Send high‑severity security alerts to Slack, Discord or Teams |
| `TRUST_PROXY`, `TRUSTED_IP_HEADER`, `ALLOWED_ORIGINS` | Real client IPs behind Caddy or Cloudflare, and allowed WebSocket origins |
| `REG_PER_IP_HOUR`, `POW_BITS`, `MAX_CONN_PER_IP`, … | Abuse limits. Every one is listed in `server/security.js`. |

Browsers only allow microphone, camera, service workers and push over **HTTPS**. Caddy in the compose file handles certificates automatically.

## Tests

```bash
npm test                                         # protocol, link-safety, server and attack-simulation tests (SQLite)
QCHAT_TEST_PG=postgres://… QCHAT_TEST_REDIS=redis://… npm test   # + Postgres/Redis, 2 instances
PORT=3100 npm start & python3 tests/e2e.py       # full browser test (Playwright + Chrome)
```

- **`tests/crypto.test.mjs`:** the protocol's adversarial suite. It covers forward secrecy, post‑compromise security, replay, tampering, forged prekeys, one‑time‑prekey reuse, device‑certificate forgery, device‑list rollback, group fan‑out and safety numbers.
- **`tests/senderkey.test.mjs` / `tests/biggroup.test.mjs`:** sender keys (forgery by another member, replay, rotation after removal) and a real 3,500‑member group through the server: one ~4.6 KB message reaches ~7,000 device queues in about 0.25 s (SQLite) / 1.3 s (Postgres), plus the per‑account delivery quota.
- **`tests/server.test.mjs`:** the real server process, single‑instance and two‑instance (Postgres + Redis). It covers multi‑device delivery, the offline queue, cross‑instance presence, device revocation, rollback rejection, and Web Push to a fake push service. The test decrypts the push to prove it's content‑free.
- **`tests/e2e.py`:** 3 users and 4 browsers. It covers DMs, groups, media, edits and deletes, linking a second device with history copy, Status, a 1:1 video call ringing on both devices (with frame‑encryption counters checked), a 3‑way group video call with key rotation, encrypted backup round‑trip, passcode lock, a check that the local database is ciphertext only, offline delivery, and device revocation.

## Project layout

```
src/shared/      crypto.js (primitives, identities, certs), ratchet.js (PQ double ratchet), envelope.js
src/client/      app.js (UI), core.js (sessions/network), calls.js, e2ee-worker.js (frame crypto), store.js (encrypted DB), sw.js
server/          index.js (relay), store.js (chat DB), admin-store.js (separate admin DB), admin.js + admin-auth.js (dashboard API, 2FA), monitor.js (status), security.js, bus.js
src/admin/       dashboard UI
public/          static assets + built bundles
deploy/          Caddyfile, coturn config
```

## Known limits (see PROTOCOL.md §11)

- **Metadata:** the server can see who talks to whom and when. Sealed sender isn't implemented.
- **Profiles:** display name, about text and avatar are public on the server.
- **Group calls and Live** connect every participant directly (no media server), so calls work best with 8 people or fewer and Live with up to 20 viewers. Bigger broadcasts would need a media server that forwards the still‑encrypted frames.
- **Audit:** the protocol is fully specified and covered by tests, but **it has not had an independent professional audit yet**. Get one before relying on it for high‑risk use.
