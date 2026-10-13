import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { TokenBucket } from "../src/rate-limiter.js";
import {
  CT_B64_MAX_LENGTH,
  isValidRoomId,
  validateJoin,
  validateMessage,
} from "../src/validation.js";

const IV = "AAAAAAAAAAAAAAAA"; // 12 bytes
const CT = "A".repeat(24);

describe("validateJoin", () => {
  it("accepts valid room IDs", () => {
    assert.deepEqual(validateJoin({ room: "abc_DEF-123" }), { ok: true, room: "abc_DEF-123" });
    assert.equal(isValidRoomId("a".repeat(64)), true);
  });

  it("rejects invalid room IDs and shapes", () => {
    for (const room of ["short", "a".repeat(65), "has space", "../etc", "<script>", 123, null]) {
      assert.equal(validateJoin({ room }).ok, false, `room ${String(room)}`);
    }
    for (const data of [null, undefined, "room", [], { room: "valid-room", extra: 1 }]) {
      assert.equal(validateJoin(data).ok, false);
    }
  });
});

describe("validateMessage", () => {
  it("accepts a well-formed envelope", () => {
    assert.deepEqual(validateMessage({ v: 1, iv: IV, ct: CT }), {
      ok: true,
      message: { v: 1, iv: IV, ct: CT },
    });
  });

  it("rejects plaintext and extra fields", () => {
    assert.equal(validateMessage("Alice: hello").ok, false);
    assert.equal(validateMessage({ v: 1, iv: IV, ct: CT, name: "Alice" }).ok, false);
    assert.equal(validateMessage({ v: 1, iv: IV, ct: "hello world, not base64!" }).ok, false);
    assert.equal(validateMessage({ text: "hello" }).ok, false);
  });

  it("rejects bad versions, IVs and ciphertexts", () => {
    assert.equal(validateMessage({ v: 2, iv: IV, ct: CT }).error, "unsupported_version");
    assert.equal(validateMessage({ v: "1", iv: IV, ct: CT }).ok, false);
    assert.equal(validateMessage({ v: 1, iv: "AAAA", ct: CT }).ok, false);
    assert.equal(validateMessage({ v: 1, iv: IV, ct: "AAAA" }).ok, false);
    assert.equal(validateMessage({ v: 1, iv: IV, ct: 42 }).ok, false);
  });

  it("enforces the maximum ciphertext size", () => {
    assert.equal(validateMessage({ v: 1, iv: IV, ct: "A".repeat(CT_B64_MAX_LENGTH) }).ok, true);
    assert.equal(
      validateMessage({ v: 1, iv: IV, ct: "A".repeat(CT_B64_MAX_LENGTH + 4) }).error,
      "payload_too_large",
    );
  });

  it("rejects objects with a custom prototype", () => {
    const sneaky = Object.create({ polluted: true });
    Object.assign(sneaky, { v: 1, iv: IV, ct: CT });
    assert.equal(validateMessage(sneaky).ok, false);
  });
});

describe("TokenBucket", () => {
  it("allows bursts up to capacity, then refills over time", () => {
    let now = 0;
    const bucket = new TokenBucket({ capacity: 3, refillPerSecond: 1, now: () => now });
    assert.equal(bucket.tryRemove(), true);
    assert.equal(bucket.tryRemove(), true);
    assert.equal(bucket.tryRemove(), true);
    assert.equal(bucket.tryRemove(), false);
    now += 1000;
    assert.equal(bucket.tryRemove(), true);
    assert.equal(bucket.tryRemove(), false);
    now += 10_000;
    for (let i = 0; i < 3; i += 1) assert.equal(bucket.tryRemove(), true);
    assert.equal(bucket.tryRemove(), false);
  });
});
