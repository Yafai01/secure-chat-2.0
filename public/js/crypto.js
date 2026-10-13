// End-to-end encryption for Secure Chat, built only on the Web Crypto API
// (available in all modern browsers and in Node.js 22+ as globalThis.crypto).
//
// Scheme (protocol v1):
//   salt       = SHA-256("secure-chat-2.0/v1/salt/" + roomId)
//   bits[64]   = PBKDF2-HMAC-SHA-256(passphrase, salt, 600 000 iterations)
//   key        = AES-256-GCM key from bits[0..32]   (non-extractable)
//   fingerprint= SHA-256(bits[32..64])[0..8]        (safe to show and compare)
//   message    = AES-GCM(key, iv = 12 random bytes,
//                        aad = "secure-chat-2.0/v1|room:" + roomId,
//                        plaintext = JSON {id, name, text, ts})
//
// AES-GCM authenticates the ciphertext, IV and AAD, so any modification by
// the server (or anyone else) makes decryption fail. Binding the room ID into
// both the salt and the AAD means a ciphertext from one room can't be replayed
// into another.

export const PROTOCOL_VERSION = 1;
export const PBKDF2_ITERATIONS = 600_000;
export const IV_BYTES = 12;
export const MIN_PASSPHRASE_LENGTH = 8;
export const MAX_NAME_LENGTH = 40;
export const MAX_TEXT_LENGTH = 2000;
/** (6128 + 16-byte tag) bytes encode to exactly 8192 base64 chars, the server limit. */
export const MAX_PLAINTEXT_BYTES = 6128;

const SALT_PREFIX = "secure-chat-2.0/v1/salt/";
const AAD_PREFIX = "secure-chat-2.0/v1|room:";

const subtle = globalThis.crypto?.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class DecryptionError extends Error {
  constructor(message = "Message could not be decrypted or failed authentication") {
    super(message);
    this.name = "DecryptionError";
  }
}

function assertWebCrypto() {
  if (!subtle) {
    throw new Error(
      "Web Crypto is unavailable. Open the app over HTTPS or on localhost.",
    );
  }
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function roomAad(roomId) {
  return encoder.encode(AAD_PREFIX + roomId);
}

/**
 * Derives the room key and a human-comparable fingerprint from a shared
 * passphrase. Everyone using the same passphrase in the same room gets the
 * same key and fingerprint.
 *
 * @param {string} passphrase
 * @param {string} roomId
 * @param {{ iterations?: number }} [options]
 * @returns {Promise<{ key: CryptoKey, fingerprint: string }>}
 */
export async function deriveRoomKey(passphrase, roomId, { iterations = PBKDF2_ITERATIONS } = {}) {
  assertWebCrypto();
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new TypeError("Passphrase is required");
  }
  if (typeof roomId !== "string" || roomId.length === 0) {
    throw new TypeError("Room ID is required");
  }

  const salt = new Uint8Array(await subtle.digest("SHA-256", encoder.encode(SALT_PREFIX + roomId)));
  const baseKey = await subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = new Uint8Array(
    await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, baseKey, 512),
  );

  const key = await subtle.importKey("raw", bits.slice(0, 32), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
  const digest = new Uint8Array(await subtle.digest("SHA-256", bits.slice(32)));
  bits.fill(0);

  const fingerprint = toHex(digest.slice(0, 8)).toUpperCase().match(/.{4}/g).join(" ");
  return { key, fingerprint };
}

/**
 * Encrypts a chat message into a `{ v, iv, ct }` envelope.
 * @param {CryptoKey} key
 * @param {string} roomId
 * @param {{ name: string, text: string }} message
 */
export async function encryptMessage(key, roomId, { name, text }) {
  assertWebCrypto();
  if (typeof text !== "string" || text.length === 0) throw new TypeError("Message is empty");
  if (text.length > MAX_TEXT_LENGTH) throw new RangeError("Message is too long");

  const body = {
    id: bytesToBase64(crypto.getRandomValues(new Uint8Array(12))),
    name: String(name ?? "").slice(0, MAX_NAME_LENGTH),
    text,
    ts: Date.now(),
  };
  const plaintext = encoder.encode(JSON.stringify(body));
  if (plaintext.byteLength > MAX_PLAINTEXT_BYTES) throw new RangeError("Message is too long");

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv, additionalData: roomAad(roomId) }, key, plaintext),
  );

  return {
    envelope: { v: PROTOCOL_VERSION, iv: bytesToBase64(iv), ct: bytesToBase64(ct) },
    message: body,
  };
}

/**
 * Decrypts and authenticates an envelope. Throws DecryptionError on any
 * tampering, wrong key, wrong room or malformed content.
 * @returns {Promise<{ id: string, name: string, text: string, ts: number }>}
 */
export async function decryptMessage(key, roomId, envelope) {
  assertWebCrypto();
  if (!envelope || envelope.v !== PROTOCOL_VERSION) throw new DecryptionError("Unsupported message version");

  let plaintext;
  try {
    const iv = base64ToBytes(envelope.iv);
    if (iv.length !== IV_BYTES) throw new Error("bad iv");
    plaintext = await subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: roomAad(roomId) },
      key,
      base64ToBytes(envelope.ct),
    );
  } catch {
    throw new DecryptionError();
  }

  let body;
  try {
    body = JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new DecryptionError("Malformed message");
  }
  if (
    !body ||
    typeof body.id !== "string" ||
    typeof body.name !== "string" ||
    typeof body.text !== "string" ||
    typeof body.ts !== "number" ||
    body.name.length > MAX_NAME_LENGTH ||
    body.text.length > MAX_TEXT_LENGTH
  ) {
    throw new DecryptionError("Malformed message");
  }
  return { id: body.id, name: body.name, text: body.text, ts: body.ts };
}
