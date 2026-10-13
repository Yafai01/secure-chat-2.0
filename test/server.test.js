import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { io as connect } from "socket.io-client";

import { createChatServer } from "../src/server.js";

const IV = "AAAAAAAAAAAAAAAA";
const CT = "Q0lQSEVSVEVYVF9QTEFDRUhPTERFUg=="; // opaque to the server
const silent = { log() {}, warn() {} };

let server;
let baseUrl;
const clients = [];

function startServer(options = {}) {
  return new Promise((resolve) => {
    const instance = createChatServer({ logger: silent, ...options });
    instance.httpServer.listen(0, "127.0.0.1", () => {
      resolve({ ...instance, url: `http://127.0.0.1:${instance.httpServer.address().port}` });
    });
  });
}

function client(url = baseUrl, options = {}) {
  const socket = connect(url, { transports: ["websocket"], forceNew: true, reconnection: false, ...options });
  clients.push(socket);
  return socket;
}

function emit(socket, event, payload) {
  return socket.timeout(2000).emitWithAck(event, payload);
}

function connected(socket) {
  return new Promise((resolve, reject) => {
    if (socket.connected) return resolve();
    socket.once("connect", resolve);
    socket.once("connect_error", reject);
  });
}

/** Collects every `message` event a socket receives. */
function inbox(socket) {
  const received = [];
  socket.on("message", (m) => received.push(m));
  return received;
}

const tick = (ms = 150) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  server = await startServer();
  baseUrl = server.url;
});

after(async () => {
  for (const c of clients) c.close();
  await new Promise((r) => server.io.close(r));
});

describe("HTTP", () => {
  it("serves the app with security headers", async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 200);
    const csp = res.headers.get("content-security-policy");
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("x-powered-by"), null);
    const html = await res.text();
    assert.ok(!/https?:\/\/cdn/i.test(html), "no third-party scripts");
  });

  it("serves the Socket.IO client and crypto module locally", async () => {
    assert.equal((await fetch(`${baseUrl}/socket.io/socket.io.js`)).status, 200);
    assert.equal((await fetch(`${baseUrl}/js/crypto.js`)).status, 200);
  });
});

describe("rooms", () => {
  it("relays messages only to other members of the same room", async () => {
    const alice = client();
    const bob = client();
    const eve = client();
    await Promise.all([alice, bob, eve].map(connected));

    const aliceInbox = inbox(alice);
    const bobInbox = inbox(bob);
    const eveInbox = inbox(eve);

    assert.equal((await emit(alice, "join", { room: "room-alpha" })).ok, true);
    const bobJoin = await emit(bob, "join", { room: "room-alpha" });
    assert.deepEqual(bobJoin, { ok: true, count: 2 });
    assert.equal((await emit(eve, "join", { room: "room-bravo" })).ok, true);

    const envelope = { v: 1, iv: IV, ct: CT };
    assert.deepEqual(await emit(alice, "message", envelope), { ok: true });
    await tick();

    assert.deepEqual(bobInbox, [envelope]);
    assert.deepEqual(aliceInbox, [], "sender is not echoed");
    assert.deepEqual(eveInbox, [], "other rooms receive nothing");
  });

  it("stops relaying after a client switches rooms", async () => {
    const a = client();
    const b = client();
    await Promise.all([a, b].map(connected));
    const bInbox = inbox(b);

    await emit(a, "join", { room: "room-one" });
    await emit(b, "join", { room: "room-one" });
    await emit(b, "join", { room: "room-two" });

    await emit(a, "message", { v: 1, iv: IV, ct: CT });
    await tick();
    assert.deepEqual(bInbox, []);
  });

  it("refuses messages from sockets that have not joined a room", async () => {
    const lurker = client();
    await connected(lurker);
    assert.deepEqual(await emit(lurker, "message", { v: 1, iv: IV, ct: CT }), {
      ok: false,
      error: "not_in_room",
    });
  });

  it("rejects invalid room IDs", async () => {
    const c = client();
    await connected(c);
    assert.equal((await emit(c, "join", { room: "x" })).ok, false);
    assert.equal((await emit(c, "join", "room-alpha")).ok, false);
  });

  it("broadcasts presence counts", async () => {
    const a = client();
    const b = client();
    await Promise.all([a, b].map(connected));
    await emit(a, "join", { room: "presence-room" });
    const update = new Promise((resolve) => a.once("presence", resolve));
    await emit(b, "join", { room: "presence-room" });
    assert.deepEqual(await update, { count: 2 });
  });
});

describe("payload validation", () => {
  it("does not relay plaintext or malformed payloads", async () => {
    const sender = client();
    const receiver = client();
    await Promise.all([sender, receiver].map(connected));
    const received = inbox(receiver);
    await emit(sender, "join", { room: "validation-room" });
    await emit(receiver, "join", { room: "validation-room" });

    const bad = [
      "Alice: hello in plaintext",
      { v: 1, iv: IV, ct: CT, name: "Alice" },
      { v: 1, iv: "short", ct: CT },
      { v: 1, iv: IV, ct: "not base64 !!" },
      { v: 2, iv: IV, ct: CT },
      null,
    ];
    for (const payload of bad) {
      const res = await emit(sender, "message", payload);
      assert.equal(res.ok, false, JSON.stringify(payload));
    }
    await tick();
    assert.deepEqual(received, []);
  });

  it("rejects oversized ciphertext", async () => {
    const c = client();
    await connected(c);
    await emit(c, "join", { room: "size-room" });
    const res = await emit(c, "message", { v: 1, iv: IV, ct: "A".repeat(8196) });
    assert.deepEqual(res, { ok: false, error: "payload_too_large" });
  });
});

describe("rate limiting", () => {
  it("throttles message floods per socket", async () => {
    const limited = await startServer({
      limits: { message: { capacity: 3, refillPerSecond: 0.001 }, join: { capacity: 5, refillPerSecond: 1 } },
    });
    try {
      const c = client(limited.url);
      await connected(c);
      await emit(c, "join", { room: "flood-room" });
      const results = [];
      for (let i = 0; i < 5; i += 1) results.push(await emit(c, "message", { v: 1, iv: IV, ct: CT }));
      assert.deepEqual(results.map((r) => r.ok), [true, true, true, false, false]);
      assert.equal(results[4].error, "rate_limited");
    } finally {
      await new Promise((r) => limited.io.close(r));
    }
  });
});

describe("origin check", () => {
  it("rejects browser connections from foreign origins", async () => {
    const c = client(baseUrl, { transports: ["polling"], extraHeaders: { Origin: "https://evil.example" } });
    await assert.rejects(connected(c));
  });

  it("accepts same-origin browser connections", async () => {
    const c = client(baseUrl, { transports: ["polling"], extraHeaders: { Origin: baseUrl } });
    await connected(c);
    assert.equal(c.connected, true);
  });
});
