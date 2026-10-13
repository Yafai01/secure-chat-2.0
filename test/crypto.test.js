import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DecryptionError,
  MAX_TEXT_LENGTH,
  PBKDF2_ITERATIONS,
  base64ToBytes,
  bytesToBase64,
  decryptMessage,
  deriveRoomKey,
  encryptMessage,
} from "../public/js/crypto.js";
import { CT_B64_MAX_LENGTH, validateMessage } from "../src/validation.js";

// Fewer iterations keep the suite fast; one test uses the real default.
const FAST = { iterations: 1000 };
const ROOM = "test-room-1";

function flipByte(b64, index) {
  const bytes = base64ToBytes(b64);
  bytes[index] ^= 0x01;
  return bytesToBase64(bytes);
}

describe("crypto", () => {
  it("uses a high PBKDF2 iteration count by default", async () => {
    assert.ok(PBKDF2_ITERATIONS >= 600_000);
    const { key, fingerprint } = await deriveRoomKey("correct horse battery", ROOM);
    assert.equal(key.algorithm.name, "AES-GCM");
    assert.equal(key.algorithm.length, 256);
    assert.equal(key.extractable, false);
    assert.match(fingerprint, /^[0-9A-F]{4}( [0-9A-F]{4}){3}$/);
  });

  it("round-trips a message", async () => {
    const { key } = await deriveRoomKey("passphrase-1", ROOM, FAST);
    const { envelope, message } = await encryptMessage(key, ROOM, { name: "Alice", text: "hello <b>world</b>" });
    const decrypted = await decryptMessage(key, ROOM, envelope);
    assert.deepEqual(decrypted, message);
    assert.equal(decrypted.text, "hello <b>world</b>");
    assert.equal(decrypted.name, "Alice");
  });

  it("produces envelopes the server accepts, without leaking plaintext", async () => {
    const { key } = await deriveRoomKey("passphrase-1", ROOM, FAST);
    const { envelope } = await encryptMessage(key, ROOM, { name: "Alice", text: "top secret" });
    assert.deepEqual(Object.keys(envelope).sort(), ["ct", "iv", "v"]);
    assert.equal(validateMessage(envelope).ok, true);
    const serialized = JSON.stringify(envelope);
    assert.ok(!serialized.includes("top secret"));
    assert.ok(!serialized.includes("Alice"));
  });

  it("uses a fresh 96-bit IV for every message", async () => {
    const { key } = await deriveRoomKey("passphrase-1", ROOM, FAST);
    const ivs = new Set();
    for (let i = 0; i < 50; i += 1) {
      const { envelope } = await encryptMessage(key, ROOM, { name: "A", text: "same text" });
      assert.equal(base64ToBytes(envelope.iv).length, 12);
      ivs.add(envelope.iv);
    }
    assert.equal(ivs.size, 50);
  });

  it("derives the same key and fingerprint for the same passphrase and room", async () => {
    const a = await deriveRoomKey("shared secret", ROOM, FAST);
    const b = await deriveRoomKey("shared secret", ROOM, FAST);
    assert.equal(a.fingerprint, b.fingerprint);
    const { envelope } = await encryptMessage(a.key, ROOM, { name: "A", text: "hi" });
    assert.equal((await decryptMessage(b.key, ROOM, envelope)).text, "hi");
  });

  it("salts per room: same passphrase in another room gives a different key", async () => {
    const a = await deriveRoomKey("shared secret", "room-aaaaaa", FAST);
    const b = await deriveRoomKey("shared secret", "room-bbbbbb", FAST);
    assert.notEqual(a.fingerprint, b.fingerprint);
    const { envelope } = await encryptMessage(a.key, "room-aaaaaa", { name: "A", text: "hi" });
    await assert.rejects(decryptMessage(b.key, "room-bbbbbb", envelope), DecryptionError);
  });

  it("rejects a message replayed into a different room (AAD binding)", async () => {
    const { key } = await deriveRoomKey("shared secret", ROOM, FAST);
    const { envelope } = await encryptMessage(key, ROOM, { name: "A", text: "hi" });
    await assert.rejects(decryptMessage(key, "other-room", envelope), DecryptionError);
  });

  it("rejects the wrong passphrase", async () => {
    const right = await deriveRoomKey("right passphrase", ROOM, FAST);
    const wrong = await deriveRoomKey("wrong passphrase", ROOM, FAST);
    assert.notEqual(right.fingerprint, wrong.fingerprint);
    const { envelope } = await encryptMessage(right.key, ROOM, { name: "A", text: "hi" });
    await assert.rejects(decryptMessage(wrong.key, ROOM, envelope), DecryptionError);
  });

  it("detects tampering with the ciphertext, tag or IV", async () => {
    const { key } = await deriveRoomKey("passphrase-1", ROOM, FAST);
    const { envelope } = await encryptMessage(key, ROOM, { name: "A", text: "pay Bob 10" });
    const ctLength = base64ToBytes(envelope.ct).length;

    const tamperedCt = { ...envelope, ct: flipByte(envelope.ct, 0) };
    const tamperedTag = { ...envelope, ct: flipByte(envelope.ct, ctLength - 1) };
    const tamperedIv = { ...envelope, iv: flipByte(envelope.iv, 0) };
    const truncated = { ...envelope, ct: bytesToBase64(base64ToBytes(envelope.ct).slice(0, ctLength - 1)) };

    for (const bad of [tamperedCt, tamperedTag, tamperedIv, truncated]) {
      await assert.rejects(decryptMessage(key, ROOM, bad), DecryptionError);
    }
  });

  it("rejects malformed envelopes", async () => {
    const { key } = await deriveRoomKey("passphrase-1", ROOM, FAST);
    for (const bad of [null, {}, { v: 2, iv: "", ct: "" }, { v: 1, iv: "!!", ct: "??" }, { v: 1, iv: "AAAA", ct: "AAAA" }]) {
      await assert.rejects(decryptMessage(key, ROOM, bad), DecryptionError);
    }
  });

  it("enforces message size limits that fit the server limit", async () => {
    const { key } = await deriveRoomKey("passphrase-1", ROOM, FAST);
    await assert.rejects(encryptMessage(key, ROOM, { name: "A", text: "" }), TypeError);
    await assert.rejects(encryptMessage(key, ROOM, { name: "A", text: "x".repeat(MAX_TEXT_LENGTH + 1) }), RangeError);

    // Largest allowed text in a multi-byte script still fits the server limit.
    const { envelope } = await encryptMessage(key, ROOM, { name: "N".repeat(40), text: "中".repeat(MAX_TEXT_LENGTH) });
    assert.ok(envelope.ct.length <= CT_B64_MAX_LENGTH);
    assert.equal(validateMessage(envelope).ok, true);

    // Text that would expand past the plaintext byte budget is refused client-side.
    await assert.rejects(encryptMessage(key, ROOM, { name: "A", text: "\u0001".repeat(MAX_TEXT_LENGTH) }), RangeError);
  });
});
