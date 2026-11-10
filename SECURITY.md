# QChat security hardening

This file covers what protects the **server**, the **accounts** and the **users** against attacks, and how each defence is tested. The cryptography is described separately in [PROTOCOL.md](PROTOCOL.md).

> **Honest scope.** No system is "unhackable". The goal is defence in depth: many independent layers, each tested, so that one failure isn't fatal.
>
> Very large network floods (gigabits per second of junk traffic) can't be stopped by any application. They must be absorbed upstream by Cloudflare, your hosting provider's DDoS protection, or a similar service. QChat is built to sit behind one (see §6).

## 1. Man‑in‑the‑middle (MITM)

| Layer | Protection |
|---|---|
| Messages, calls, Live | End‑to‑end post‑quantum encryption. A MITM who fully controls the network **or the server** still gets only ciphertext. |
| Identity | Every device key is signed by the account key. Device lists are signed and versioned, so the server can't add devices or roll back the list. |
| Detecting a swapped key | Safety numbers. **Strict key‑change mode:** if a contact's identity key changes, you can't send to them until you verify the new code or explicitly accept it. |
| Transport | HTTPS only: TLS 1.2/1.3 at Caddy, HSTS with `preload`, automatic redirect to HTTPS, and `upgrade-insecure-requests`. |
| Hijacking the WebSocket from another site | The server checks the `Origin` header (`ALLOWED_ORIGINS`) and blocks and logs foreign origins. |
| Injected scripts | Strict CSP (`script-src 'self'`, no inline scripts, no `eval`). Also `frame-ancestors 'none'` and `X-Frame-Options: DENY` against clickjacking, `nosniff`, and same‑origin COOP/CORP. |
| Call media | The browser's usual call encryption, plus a frame encryption layer whose keys travel over the PQ channel. |

## 2. Hacking the server

**Input checks**
- Every WebSocket frame is parsed defensively and must be a JSON object with a type.
- Envelopes are shape‑checked (sizes, field types, at most 1500 recipients). Their contents stay opaque.
- Usernames, device IDs, keys and prekeys are verified cryptographically.

**File serving**
- Only known file types from `public/` are served.
- Path traversal (`..`, encoded or not), null bytes and dotfiles are refused.
- Source code, `.env` files and similar are never reachable.

**Scanner detection**
- Requests for typical attack paths (`/.env`, `/.git`, `/wp-login.php`, `/phpmyadmin`, …) are logged as `scanner_probe`.
- The requesting IP is automatically banned after a few probes.

**Containers**
- The app runs as an unprivileged user on a read‑only filesystem, with all Linux capabilities dropped and `no-new-privileges`.
- Memory is capped and logs are rotated.

**Network layout**
- Postgres and Redis sit on an internal network with no route to the internet, and Redis requires a password.
- Only Caddy (ports 80/443) and the TURN relay are reachable from outside.
- The TURN relay refuses to forward into private networks (SSRF protection) and has bandwidth limits.

**Secrets**
- Every secret comes from `.env`, and you generate each one yourself.
- IP addresses in the security log are stored as keyed hashes (`IP_HASH_SECRET`), never in plain form.

**Errors**
- Clients get generic error codes only, never stack traces.
- Unhandled errors are logged, not exposed.

## 3. Detecting access‑control attacks

The server records **security events** in the database and as JSON lines in its log (for a SIEM or log tool). High‑severity events can also be sent to a webhook (`SECURITY_WEBHOOK_URL`, works with Slack, Discord and Teams).

| Event | Triggered by | Automatic response |
|---|---|---|
| `account_takeover_attempt` | Someone tries to add a device to an existing account with a wrong recovery key | The **account owner's devices are alerted immediately**. The IP gets strike points. |
| `account_locked` | 5 wrong recovery keys for one username within 15 minutes | Enrolment for that username is locked for 15 minutes, even for the correct key, and the owner is alerted. |
| `bad_device_signature` | A forged device login | Owner alerted; IP gets strike points. |
| `device_linked` | A new device is linked to an account | Owner's other devices are alerted; the device appears in Settings. |
| `auth_failed` | Failed logins | 20 failures from one IP in 10 minutes ban the IP. |
| `ws_bad_origin` | Cross‑site WebSocket hijacking attempt | Blocked; IP gets strike points. |
| `enumeration_suspected` | Too many username lookups | Lookups throttled. |
| `admin_auth_failed` | Wrong admin token | IP gets strike points; repeated failures ban it. |
| `ip_banned` | Too many strike points within 10 minutes | Ban of 15 minutes, doubling for repeat offenders, up to 24 hours. |

**Strike points.** Every suspicious action adds points to the requesting IP: bad JSON, bad envelopes, floods, wrong origin, scanner paths, bad proof‑of‑work and so on. Reaching the threshold triggers an automatic ban.

**Admin dashboard.** At `https://your-domain/admin`, enabled only when `ADMIN_TOKEN` is set; it can be limited to specific IPs with `ADMIN_IPS`. It shows:
- live counts of events, bans, online devices and unauthenticated sockets;
- events by type and a filterable event log;
- ban and unban controls.

## 4. Phishing, scam links and impersonation

Messages are end‑to‑end encrypted, so **the server never sees links**. All checks run on the user's device, and nothing about a link is sent anywhere.

**Every link is checked before it can open**
- Links never open directly. Each one goes through a safety screen that shows the **real destination**.
- **Dangerous** links (red, with a warning under the message) require ticking "I understand this may be a scam". Warning signs checked:
  - look‑alike spellings of brands (`paypa1.com`, `g00gle.com`);
  - brand names on unofficial domains (`mpesa-refund.click`);
  - `@` tricks (`paypal.com@evil.com`);
  - raw IP addresses;
  - look‑alike international characters (`xn--…`);
  - `.zip` and `.mov` domains;
  - installer downloads;
  - log‑in, verify or claim lures.
- **Caution** links (yellow) show their reasons: link shorteners, plain `http`, scam‑prone domain endings, or links from strangers.

**Unknown contacts**
- A first message from someone you've never chatted with shows a warning bar, with **Block & report** and **I know them** buttons.
- Every link from a stranger is flagged.

**Social engineering**
- Messages asking for a recovery key, passcode, one‑time code, PIN or seed phrase get a warning: "QChat will never ask for them".
- So do messages claiming to be "QChat support / team / security".

**Recovery‑key leak guard.** If you try to send your recovery key in a chat, QChat stops you and explains it's a scam.

**Dangerous files.** Executables, installers (`.exe`, `.apk`, `.msi`, `.dmg`, `.js`, `.vbs`, macro documents …) and double extensions (`invoice.pdf.exe`) are flagged, and downloading them needs explicit confirmation.

**Impersonation**
- Reserved usernames (`admin`, `support`, `qchat…`, `security`, `official` …) can't be registered.
- Display names that imitate official accounts are refused.
- Invisible and direction‑override characters (used to disguise names) are stripped.
- Chats always show the real `@username` next to the display name.

**Reporting**
- "Report" sends only *who* and *why*; message content stays encrypted.
- Accounts reported by 5 different people within 24 hours are restricted to 10 new conversations per day.

## 5. Spam and abuse

**Proof‑of‑work at sign‑up and device linking.** Each attempt requires solving a small computing puzzle: about 0.6 seconds in a browser at the default difficulty. The puzzles automatically get harder when many sign‑ups happen at once.

**Limits per network (IP address)**
- 10 new accounts per hour (`REG_PER_IP_HOUR`).
- 30 open connections and 60 new connections per minute.
- 600 page requests per minute.

**Limits per account**
- 120 username lookups per minute (stops people scanning for usernames).
- New conversations per day: 60 for accounts less than a week old, 300 otherwise, 10 if the account has been reported.
- 900 messages per minute.
- The offline queue holds at most 5000 messages per device.

**Shared across servers.** With Redis, all these counters and bans are shared between server instances, so an attacker can't spread out to dodge them.

## 6. DDoS

| Layer | What it handles |
|---|---|
| **Upstream (you configure this)** | Large network floods. Put the domain behind **Cloudflare** (it supports WebSockets) or your host's DDoS protection, and set `TRUSTED_IP_HEADER=cf-connecting-ip`. Then firewall your server so only the provider's IP ranges can reach ports 80/443. |
| Caddy | TLS termination, a 10‑second header‑read timeout (stops slowloris), a 25 MB body cap, health‑checked load balancing over several app instances. |
| App: HTTP | Per‑IP request rate limit, header and request timeouts, a cap on header count, automatic bans. |
| App: WebSocket | Per‑IP connection caps, a connection‑rate limit, a **20‑second login deadline** for new sockets, a **600 KB size limit before login**, a per‑socket message rate limit that escalates to bans. |
| App: cost | The offline queue and the security log expire automatically. Proof‑of‑work makes bulk account creation expensive. |
| Scale | Run more `qchatN` services behind Caddy. Postgres and Redis keep them in sync. |

## 7. Tests

The defences above are checked by automated attacks against real server processes:

```
npm test   # crypto (13) + link safety (6) + server (3) + security attacks (4)
```

`tests/security.test.mjs` simulates:
- a vulnerability scanner (it gets auto‑banned while other users are unaffected);
- path traversal;
- cross‑site WebSocket hijacking;
- connection floods and message floods (they end in bans);
- oversized frames and malformed envelopes;
- sign‑ups that skip the proof‑of‑work, reserved and impersonating names, and mass registration;
- 5 recovery‑key guesses against a real account (the owner's device receives every alert, then the account locks);
- username enumeration, new‑conversation spam and reports;
- admin dashboard brute force.

`tests/e2e.py` (real browsers) includes a stranger who sends a fake "QChat Support" message with a typosquatted PayPal link and an `invoice.pdf.exe`. The test checks that each warning appears, that the link can't be opened without acknowledgement, that the file download needs confirmation, and that sending the recovery key is intercepted.

## 8. Operator checklist

1. Generate every secret in `.env` with `openssl rand -base64 32`.
2. Put the domain behind Cloudflare or your provider's DDoS protection. Allow only its IP ranges to reach 80/443.
3. Set `ADMIN_TOKEN` and, ideally, `ADMIN_IPS`. Point `SECURITY_WEBHOOK_URL` at a channel you watch.
4. Keep the OS, Docker images and npm dependencies updated (`npm audit`, `docker compose pull`).
5. Back up the Postgres volume. It contains no message content, only public keys and undelivered ciphertext.
6. Commission an independent penetration test and protocol audit before high‑risk use.
