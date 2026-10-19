# Secure Chat 2.0

A minimal real-time group chat in which messages are encrypted in the browser before they are sent. Clients that share the same passphrase can read each other's messages; the Node.js/Socket.IO server only relays ciphertext and never sees the passphrase or plaintext.

## Features

- Real-time messaging over Socket.IO.
- Client-side AES-256-CBC encryption (CryptoJS) with a random IV per message.
- Shared-passphrase rooms: a key is derived from the passphrase in the browser; messages that cannot be decrypted are flagged.
- Server relays encrypted payloads only.
- Single-page light-theme UI with animated chat bubbles; no build step.

## How it works

1. Each user enters a display name and a shared passphrase, then connects.
2. Outgoing messages (`name: text`) are encrypted with AES using a key derived from the passphrase (SHA-256) and a fresh random IV, and sent as `iv:ciphertext`.
3. The server broadcasts the payload to all connected clients.
4. Each client attempts to decrypt with its own passphrase and displays the result.

## Tech stack

- Node.js 22+, Express (static file server)
- Socket.IO
- CryptoJS (loaded from cdnjs)
- Plain HTML, CSS, and JavaScript

## Getting started

### Prerequisites

- Node.js 22 or newer and npm

### Install and run

```bash
npm install
npm start
```

Open `http://localhost:3000` in two or more browser tabs, use the same passphrase in each, and start chatting. Set the `PORT` environment variable to use a different port.

## Project structure

```
server.js           # Express + Socket.IO server that relays messages
public/index.html   # Chat UI and client-side encryption
```

## Security note

This is an educational demo, not a production-grade secure messenger. In particular, the key is derived with a single unsalted SHA-256 hash rather than a password-based KDF, messages are not authenticated (no MAC/AEAD), there is no identity verification, and decrypted text is rendered as HTML. Do not rely on it to protect sensitive information.
