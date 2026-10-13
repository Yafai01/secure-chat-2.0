# Secure Chat 2.0

End-to-end encrypted chat rooms protected by a shared passphrase, built with Node.js, Socket.IO and the browser's Web Crypto API.

## What it does

People who know the same **room ID** and **passphrase** can chat in real time. Each browser derives an encryption key from the passphrase and encrypts every message before sending it. The server is a blind relay: it forwards opaque ciphertext to the other members of the same room and never sees passphrases, keys, names or message text. Nothing is stored on the server; when everyone leaves, the conversation is gone.

## Features

- **Rooms** – join by room ID (or generate a random one); the server relays messages only within the room.
- **End-to-end encryption** – AES-256-GCM with a fresh random 96-bit IV per message, so every message is encrypted and authenticated. Tampered, truncated or replayed-into-another-room messages are rejected.
- **Passphrase-based key derivation** – PBKDF2-HMAC-SHA-256 with 600,000 iterations and a per-room salt.
- **Safety code** – a short fingerprint derived from the room key. If two people's safety codes match, they're using the same passphrase.
- **No third-party crypto or CDN scripts** – only the built-in Web Crypto API; all assets are served by the app itself under a strict Content Security Policy.
- **XSS-safe rendering** – names and messages are rendered with `textContent`, never as HTML.
- **Server hardening** – strict payload validation (shape, base64, size), per-connection rate limiting, a same-origin check on the WebSocket handshake, a 16 KB packet cap, and logs that contain no message content or room IDs.
- **Shareable room links** – `/#room=<id>` pre-fills the room ID. The passphrase is never put in the link.

## Threat model and limitations

Read this before relying on the app.

**What it protects against**

- A curious or compromised **relay server**, or anyone watching the network, reading message contents or display names.
- The server (or anyone in the path) **modifying** messages: AES-GCM authentication makes decryption fail on any change.
- Moving ciphertext between rooms: the room ID is bound into both the key derivation salt and the GCM additional data.
- People in the same room **without the passphrase**: they only see "couldn't be decrypted" notices.

**What it does not protect against**

- **Shared-secret model.** Anyone who knows the passphrase can read *and send* messages in that room, and can claim any display name. There's no per-user identity, no signatures and no way to tell participants apart cryptographically.
- **No identity verification.** The safety code only proves that people share the same passphrase. It doesn't prove who they are.
- **No forward secrecy.** If the passphrase leaks later, anyone who recorded the ciphertext can decrypt past messages. Use a new room and passphrase for each conversation.
- **Weak passphrases can be brute-forced** offline by someone holding ciphertext. PBKDF2 slows this down but doesn't prevent it. Use a long, random passphrase (for example, 5+ random words), and share it over a separate channel.
- **Metadata is visible to the server:** IP addresses, room IDs, when people connect, how many people are in a room, and message timing and sizes.
- **The server serves the client code.** A malicious server operator could ship modified JavaScript that leaks the passphrase. As with any web-based E2E app, you have to trust whoever serves the page, or host it yourself.
- **Replay within a room.** Clients ignore duplicate message IDs during a session, but a malicious server could redeliver old ciphertext to someone who joins later.
- **Endpoint security** (malware, browser extensions, screen capture) is out of scope.
- This project has **not been independently audited**.

## How the encryption works

All of this lives in [`public/js/crypto.js`](public/js/crypto.js) and runs in the browser:

```
salt        = SHA-256("secure-chat-2.0/v1/salt/" + roomId)
bits (64 B) = PBKDF2-HMAC-SHA-256(passphrase, salt, 600 000 iterations)
key         = AES-256-GCM key from bits[0..32]   (non-extractable CryptoKey)
safety code = first 8 bytes of SHA-256(bits[32..64]), shown as hex

per message:
  iv        = 12 random bytes
  aad       = "secure-chat-2.0/v1|room:" + roomId
  plaintext = JSON { id, name, text, ts }
  envelope  = { v: 1, iv: base64(iv), ct: base64(AES-GCM(key, iv, aad, plaintext)) }
```

The salt is deterministic per room (everyone in the room has to derive the same key without talking to each other first), so it isn't secret. It still stops a single precomputed table from working across rooms.

The server only accepts envelopes shaped exactly like `{ v: 1, iv, ct }` with valid base64, a 12-byte IV and a ciphertext of at most 8192 base64 characters. It rejects anything else, including extra unencrypted fields.

## Tech stack

- **Server:** Node.js 22+, Express 4 (static files and security headers), Socket.IO 4 (WebSocket relay)
- **Client:** plain HTML, CSS and ES modules; Web Crypto API; the Socket.IO client served by the app
- **Tests:** the built-in Node test runner (`node:test`) and `socket.io-client`

## Project structure

```
.
├── server.js              # Entry point: reads env vars and starts the server
├── src/
│   ├── server.js          # Express + Socket.IO setup, rooms, relay, headers, origin check
│   ├── validation.js      # Validation for join requests and encrypted envelopes
│   └── rate-limiter.js    # Token-bucket rate limiter
├── public/
│   ├── index.html         # UI markup
│   ├── css/styles.css     # Styles
│   └── js/
│       ├── app.js         # UI logic and socket handling
│       └── crypto.js      # Key derivation and AES-GCM encryption (Web Crypto)
└── test/
    ├── crypto.test.js     # Round trip, tamper detection, per-room salts, limits
    ├── server.test.js     # Room isolation, validation, rate limiting, headers, origin check
    └── validation.test.js # Validator and rate-limiter unit tests
```

## Prerequisites

- Node.js **22 or newer** and npm
- A modern browser. Web Crypto only works in a **secure context**: `https://` or `http://localhost`.

## Setup and running

```bash
npm ci          # install dependencies from the lockfile
npm start       # start the server on http://localhost:3000
npm run dev     # start with automatic restart on file changes
```

Open `http://localhost:3000` in two browser windows, enter the same room ID and passphrase in both, and start chatting.

### Environment variables

The server reads these from the environment. All are optional; see [`.env.example`](.env.example).

| Variable          | Default   | Description                                                                 |
| ----------------- | --------- | --------------------------------------------------------------------------- |
| `PORT`            | `3000`    | HTTP port                                                                   |
| `HOST`            | `0.0.0.0` | Interface to bind                                                           |
| `ALLOWED_ORIGINS` | *(empty)* | Comma-separated list of extra origins allowed to connect. Same-origin connections are always allowed. |

To load them from a `.env` file: `node --env-file=.env server.js`.

## Tests

```bash
npm test        # runs every *.test.js file with node --test
npm run check   # syntax-checks the server and client sources
```

The tests cover:

- Encryption round trip, a unique IV per message, per-room salts, and rejection of the wrong passphrase.
- Rejection of tampered ciphertext, tag or IV, truncated ciphertext, and ciphertext replayed into another room.
- Server behaviour: relaying only within a room, no echo to the sender, refusing messages from sockets that haven't joined a room, presence counts, rejection of plaintext, malformed and oversized payloads, rate limiting, security headers, and the origin check.

## Deployment notes

- **Serve it over HTTPS.** Browsers turn off Web Crypto on plain HTTP (except on `localhost`), and TLS protects the client code in transit. Put the app behind a TLS-terminating reverse proxy (for example nginx or Caddy) that forwards WebSocket upgrades.
- If the page is served from a different origin than the socket server, add that origin to `ALLOWED_ORIGINS`.
- Rate limits are per connection and kept in memory. For running several instances or for protection against abuse from many IPs, add limits at the proxy, plus a Socket.IO adapter (for example Redis) so rooms span instances.
- `GET /healthz` returns `{"status":"ok"}` for health checks.

## License

No license has been chosen yet. All rights are reserved by the author until one is added.
