# QChat protocol v2: specification and threat model

This document is written so an independent reviewer can audit the design. The code it describes is in `src/shared/` (crypto, ratchet, envelopes), `src/client/` (client) and `server/` (relay). The adversarial tests are in `tests/crypto.test.mjs`.

## 1. Primitives

| Purpose | Algorithm | Library |
|---|---|---|
| Signatures | **ML‑DSA‑65** (FIPS 204) | `@noble/post-quantum` |
| Key encapsulation | **ML‑KEM‑768** (FIPS 203) | `@noble/post-quantum` |
| Symmetric encryption | AES‑256‑GCM, random 96‑bit IV | WebCrypto |
| KDF | HKDF‑SHA256; chain steps HMAC‑SHA256 | `@noble/hashes` |
| Passcode KDF | Argon2id (m = 19 MiB, t = 2, p = 1) | `@noble/hashes` |
| Signed encodings | Canonical JSON (sorted keys), domain‑separated (`qchat-…-v2\n`) | — |

No classical public‑key primitive is used anywhere in the message, login or call‑key paths.

## 2. Identities

- **Account identity key (AIK):** ML‑DSA‑65, derived from a 32‑byte seed. The **recovery key** is `QC1-` followed by base64url of `aikSeed(32) ‖ backupSeed(64) ‖ SHA256(…)[0..4]`.
- **Device:** each device generates its own ML‑DSA‑65 key. The AIK signs a **device certificate** `{user, device, sigPk, created, name}`.
- **Device list:** the AIK signs `{user, version, devices[], ts}`. The server stores the latest list. Clients pin the highest `version` they've seen and refuse lower ones (anti‑rollback). The server can't add a device, because it can't forge AIK signatures. It *can* withhold devices, which is a denial of service, not a confidentiality break.
- **Safety number:** 60 digits from `SHA256` of both users' AIKs. One number covers all of a user's devices.
- **Key‑change policy:** trust on first use. If a contact's AIK changes, the chat shows a warning and their "verified" flag is cleared.

## 3. Login

- **Existing device:** the server sends a 32‑byte nonce. The device signs `{user, device, nonce}` with its device key.
- **New account or new device (enrollment):**
  1. The device sends its certificate, a new device list with `version + 1`, a signed prekey (SPK) and up to 100 one‑time prekeys (OTPKs). All prekeys are signed by the device key.
  2. It signs `{user, device, nonce}` with the device key, and `{user, device, nonce, list.version}` with the AIK.
  3. The server checks every signature, and that the list's version is newer and contains the device.
- A stolen server database contains only public keys, so it can't be used to log in.

## 4. Sessions: the PQ double ratchet

There is one session per (local device, remote device) pair. The two directions are independent "epochs".

**Starting an epoch (sender side):**
- **`pre` (first contact):** encapsulate to the remote's SPK and, if available, an OTPK. Let `ss = ss_spk ‖ ss_otpk`. The server hands out each OTPK once, using an atomic `DELETE … RETURNING`. The receiver deletes the OTPK secret after first use.
- **`rk` (ratchet):** encapsulate to the newest ratchet public key the remote advertised.
- **Chain key:** `CK₀ = HKDF(ss, salt = epochId, info = "qchat-chain-v2|fromUser|fromDev|toUser|toDev")`.

**Per message:**
- `mk = HMAC(CK, 0x01)`
- `CK' = HMAC(CK, 0x02)`

**Ratchet keys:** each side advertises a fresh ML‑KEM‑768 ratchet key (`h.r`) until the peer acknowledges it (`h.a`). When the peer starts an epoch on that key, the owner rotates to a new one. Old secrets are deleted once the peer has moved on, or after at most 3 generations or 7 days.

**Header** (authenticated by the envelope signature, not encrypted): `{e, n, a, k?, r?, ae?}`. Here `k` is the epoch initializer, sent until the peer echoes `ae`.

**Limits:** at most 2000 skipped keys per epoch. Skipped keys expire after 7 days. At most 4 receive epochs are kept per session.

**Properties** (each one is a test in `tests/crypto.test.mjs`):
- **Forward secrecy:** a full state compromise doesn't reveal earlier epochs. Their chain keys, ratchet secrets and OTPK secrets are gone.
- **Post‑compromise security:** after one round trip with fresh ratchet keys, a stolen session copy can't decrypt new epochs.
- **Replay / duplicate rejection:** each message key is used once. Envelope IDs are de‑duplicated too.

**Prekey lifecycle:** the SPK rotates every 7 days, and old SPK secrets are deleted 30 days later. OTPKs are refilled to 60 when the server reports fewer than 20.

## 5. Envelopes

For each payload, the sender:
1. Encrypts it once: `ct = AES‑256‑GCM(K, payload, AAD = "qchat-env-v2|id|from|fromDev")`, with a random `K`.
2. Wraps `K` for each recipient device as `w = K ⊕ HKDF(mk, "qchat-wrap-v2")`. Each `mk` is used exactly once.
3. Signs the canonical encoding of `{v, from, fd, id, iv, ct, keys[{u,d,h,w}]}` with the sender's **device key**.

The recipient verifies the signature against the sender's certified device key *before* touching ratchet state. Decryption runs on a cloned session, which is committed only after AES‑GCM succeeds.

**What the server sees:** sender user and device, recipient users and devices, sizes, times, and ratchet headers (epoch IDs, counters, ratchet public keys). It never sees content, group names, members, reactions, receipts, statuses or call keys.

## 6. Multi‑device

- Every payload is also encrypted to the sender's own other devices. Direct messages carry `to`, so those devices can file the message in the right chat.
- **History transfer:** a new device asks for history with `sync_req`. An existing device asks the user to confirm, then sends chunked `sync_data` over the ratchet.
- **New‑device alert:** every newly linked device triggers an alert on the account's other devices.

## 7. Groups (up to 3,500 members)

Groups are managed by clients. Group **messages** use **sender keys** (the approach Signal and WhatsApp use for large groups), so a message costs the same — about 4.6 KB plus content — whether the group has 3 or 3,500 members.

- **Sender chain:** every device keeps one chain per group: `{kid, CK, n}`. For each message: `mk = HMAC(CK, 0x01)`, then `CK = HMAC(CK, 0x02)` (forward secrecy inside the chain); the message key is `HKDF(mk, "qchat-gmsg-v1|g")`.
- **Key distribution:** the chain key goes to every member device as a `skey` payload inside the normal **post‑quantum double ratchet** (ML‑KEM‑768 + ML‑DSA‑65), in envelopes of up to 1,000 devices. A device that missed it (new device, unreachable at the time) asks the sender with `skey_req`; the sender answers in batches, never with messages older than when that person could have joined.
- **Envelope v3:** `{v:3, from, fd, id, g, kid, n, iv, ct, sig}`; `ct = AES‑256‑GCM(key, payload, AAD = "qchat-env-v3|id|from|fd|g|kid|n")`, `sig` = the sender device's **ML‑DSA‑65** signature. Other members hold the chain key but can't forge messages in someone else's name. A chain is only accepted from the device that owns it.
- **Rotation:** when anyone leaves or is removed, or a member unlinks a device, every sender starts a fresh chain, so they can't read anything sent afterwards. Added members get the chain from that point on only.
- **Fan‑out:** the client addresses `{u}` (a user); the server expands it to all of that user's current devices with bulk queries, in one transaction, with a per‑account delivery quota (`DELIVERIES_PER_HOUR`).
- **Group metadata** (name, members, admins) is a signed, encrypted payload. It's only accepted from current admins, or from the creator when the group is first seen. Above 256 members it goes via the group key, and pairwise to people just added or removed.
- **Large groups (over 256):** no per‑member delivered/read receipts or typing indicators (like WhatsApp), and they're not used as a Status audience. Calls are for groups of up to 8.

## 8. Calls

**Signalling** (`ring` / `join` / `offer` / `answer` / `key` / `leave`) travels in ratchet envelopes. The DTLS certificate fingerprints inside the SDP are therefore authenticated by ML‑DSA.

**Media frame encryption:**
- Each participant has a random 256‑bit media key, delivered to each peer inside the ratchet‑encrypted offer or answer.
- Every encoded frame is encrypted with AES‑256‑GCM in a Worker, using Encoded Transforms (`RTCRtpScriptTransform`, or `createEncodedStreams` as a fallback).
- Frame layout: `[codec header: 10 B for a VP8 key frame / 3 B for a delta frame / 1 B for audio] [ciphertext+tag] [IV 12 B] [keyId 1 B]`. The header is cleartext but authenticated as AAD.
- If a browser lacks Encoded Transforms, it can't make calls. There is no unencrypted fallback.

**DTLS‑SRTP** (classical ECDHE) still wraps the result. A future quantum attacker who breaks the DTLS layer only sees AES‑256‑GCM ciphertext, whose keys were exchanged with ML‑KEM.

**Key rotation:** when someone leaves a group call, the remaining participants rotate their media keys (`key` message, new keyId).

**Group calls** are a full mesh, up to 8 people.

## 8b. Live streams (Status → Go Live)

**Announcing a live:**
- The host sends `live_start {live, title, started}` to their contacts (people with a direct chat or a shared group). It's a normal queued ratchet envelope, with a push notification of kind `live`.
- `live_end` is sent the same way.

**Joining and media:**
- A viewer sends `live_join` to the host's device. The host answers with `live_offer`, which carries:
  - the SDP for a send‑only WebRTC connection;
  - the host's random 256‑bit **media key**;
  - the last 30 comments.
  Every one of these messages is ratchet‑encrypted and ML‑DSA‑signed.
- Frames are encrypted exactly as in calls (§8).

**Comments and hearts:**
- Viewers send `live_comment` and `live_react` to the host only.
- The host rate‑limits them, then re‑broadcasts them to every viewer as `live_c` and `live_r`, signed by the host's device.
- The server never sees comments, hearts, the title or the media key.

**Limits:**
- Each viewer gets their own connection from the host, so a viewer who leaves stops receiving frames immediately.
- The cap is 20 viewers, because the phone uploads a separate stream to each one.

## 9. Local storage

- Every IndexedDB value is AES‑256‑GCM‑encrypted with a data key (DEK), with the record's key name as AAD.
- **No passcode:** the DEK is wrapped by a non‑extractable WebCrypto key held by the browser.
- **With a passcode:** the DEK is wrapped by an Argon2id‑derived key, and nothing usable is stored until unlock. Auto‑lock reloads the page, which drops all secrets from memory.
- **Encrypted backup:** `QCB1 ‖ IV ‖ AES‑256‑GCM(HKDF(aikSeed ‖ backupSeed, "qchat-backup-v1"), JSON, AAD = "qchat-backup-v1|user")`.

## 10. Push notifications

Web Push (VAPID, RFC 8291 `aes128gcm`) is sent only to devices with no live connection, and only for envelopes the sender marked as notifiable (messages, call rings). The payload is just `{from, kind}`; message content is never included.

## 11. Threat model: what is *not* protected

- **Metadata.** The server learns the social graph (who talks to whom), message timing and sizes, IP addresses, and the ratchet headers. "Sealed sender" and padding aren't implemented.
- **Public profiles.** Display name, about text and avatar are stored on the server in plaintext, like a public profile.
- **Compromised devices.** A device that is compromised while unlocked exposes everything on it. Every linked device holds the AIK, so an attacker with one could link more devices. The new‑device alert and the device list in Settings make this visible.
- **First contact (TOFU).** The first time you contact someone, you trust the identity key the server returns until you compare safety numbers.
- **Endpoint security.** Browser extensions, malicious updates to the hosted app, and OS‑level malware are out of scope. Serving the app from a domain you control, over HTTPS, is the trust anchor.
- **Group membership.** Admins are trusted to manage membership. There's no cryptographic group state agreement like MLS.
- **Audit status.** The primitives library is audited. **This protocol and code have not been independently audited yet.** This document and the test suite are meant to make that review straightforward.
