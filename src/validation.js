// Server-side validation of everything a client can send.
//
// The server never sees plaintext or keys. It only checks that payloads have
// the expected *shape* (an AES-GCM envelope) and stay within size limits, so
// that it can't be used as a generic relay for arbitrary data.

export const PROTOCOL_VERSION = 1;

/** Room IDs: URL-safe characters only, long enough to be hard to guess. */
export const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{6,64}$/;

/** 12-byte AES-GCM IV encoded as standard base64 (always 16 characters). */
export const IV_B64_LENGTH = 16;

/** Ciphertext limits (base64 characters). 16-byte GCM tag => min 24 chars. */
export const CT_B64_MIN_LENGTH = 24;
export const CT_B64_MAX_LENGTH = 8192;

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function isBase64(value) {
  return (
    typeof value === "string" &&
    value.length % 4 === 0 &&
    BASE64_PATTERN.test(value)
  );
}

/**
 * @param {unknown} roomId
 * @returns {boolean}
 */
export function isValidRoomId(roomId) {
  return typeof roomId === "string" && ROOM_ID_PATTERN.test(roomId);
}

/**
 * Validates a `join` request: `{ room: string }`.
 * @returns {{ ok: true, room: string } | { ok: false, error: string }}
 */
export function validateJoin(data) {
  if (!isPlainObject(data)) return { ok: false, error: "invalid_request" };
  const keys = Object.keys(data);
  if (keys.length !== 1 || keys[0] !== "room") {
    return { ok: false, error: "invalid_request" };
  }
  if (!isValidRoomId(data.room)) return { ok: false, error: "invalid_room" };
  return { ok: true, room: data.room };
}

/**
 * Validates an encrypted message envelope: `{ v: 1, iv: base64, ct: base64 }`.
 * Extra fields are rejected so nothing unencrypted can piggyback on a message.
 * @returns {{ ok: true, message: { v: number, iv: string, ct: string } } | { ok: false, error: string }}
 */
export function validateMessage(data) {
  if (!isPlainObject(data)) return { ok: false, error: "invalid_payload" };

  const keys = Object.keys(data).sort();
  if (keys.length !== 3 || keys[0] !== "ct" || keys[1] !== "iv" || keys[2] !== "v") {
    return { ok: false, error: "invalid_payload" };
  }
  if (data.v !== PROTOCOL_VERSION) return { ok: false, error: "unsupported_version" };
  if (!isBase64(data.iv) || data.iv.length !== IV_B64_LENGTH) {
    return { ok: false, error: "invalid_payload" };
  }
  if (typeof data.ct !== "string" || data.ct.length > CT_B64_MAX_LENGTH) {
    return { ok: false, error: "payload_too_large" };
  }
  if (data.ct.length < CT_B64_MIN_LENGTH || !isBase64(data.ct)) {
    return { ok: false, error: "invalid_payload" };
  }
  return { ok: true, message: { v: data.v, iv: data.iv, ct: data.ct } };
}
