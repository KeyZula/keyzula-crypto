import { fromB64, toB64, utf8Decode, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";

export const SYMMETRIC_KEY_BYTES = 32;
const NONCE_BYTES = 24;
const ENC_VERSION = "v1";

declare const symmetricKeyBrand: unique symbol;
/** 32-byte XChaCha20-Poly1305 key. */
export type SymmetricKey = Uint8Array & { readonly [symmetricKeyBrand]: true };

declare const encStringBrand: unique symbol;
/** Serialized ciphertext: `v1.<nonce>.<ciphertext>` (base64url). */
export type EncString = string & { readonly [encStringBrand]: true };

export function asSymmetricKey(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== SYMMETRIC_KEY_BYTES) {
    throw new CryptoError("Key must be 32 bytes.", "INVALID_KEY");
  }
  return bytes as SymmetricKey;
}

export function generateSymmetricKey(): SymmetricKey {
  return asSymmetricKey(sodium().randombytes_buf(SYMMETRIC_KEY_BYTES));
}

export function randomBytes(length: number): Uint8Array {
  return sodium().randombytes_buf(length);
}

export function isEncString(value: unknown): value is EncString {
  return typeof value === "string" && /^v1\.[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{22,}$/.test(value);
}

/**
 * XChaCha20-Poly1305 with a random 192-bit nonce. `aad` binds the ciphertext to its context
 * (e.g. the item id) so it cannot be moved to another record.
 */
export function encryptBytes(key: SymmetricKey, plaintext: Uint8Array, aad: string): EncString {
  const s = sodium();
  const nonce = s.randombytes_buf(NONCE_BYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, utf8Encode(aad), null, nonce, key);
  return `${ENC_VERSION}.${toB64(nonce)}.${toB64(ciphertext)}` as EncString;
}

export function decryptBytes(key: SymmetricKey, value: EncString | string, aad: string): Uint8Array {
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== ENC_VERSION) {
    throw new CryptoError("Unrecognized ciphertext format.", "INVALID_FORMAT");
  }
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    nonce = fromB64(parts[1]!);
    ciphertext = fromB64(parts[2]!);
  } catch {
    throw new CryptoError("Could not decode ciphertext.", "INVALID_FORMAT");
  }
  if (nonce.length !== NONCE_BYTES) {
    throw new CryptoError("Invalid nonce length.", "INVALID_FORMAT");
  }
  try {
    return sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, utf8Encode(aad), nonce, key);
  } catch {
    throw new CryptoError("Decryption failed: wrong key or modified data.", "DECRYPT_FAILED");
  }
}

export function encryptString(key: SymmetricKey, plaintext: string, aad: string): EncString {
  return encryptBytes(key, utf8Encode(plaintext), aad);
}

export function decryptString(key: SymmetricKey, value: EncString | string, aad: string): string {
  return utf8Decode(decryptBytes(key, value, aad));
}

export function encryptJson(key: SymmetricKey, data: unknown, aad: string): EncString {
  return encryptString(key, JSON.stringify(data), aad);
}

export function decryptJson<T>(key: SymmetricKey, value: EncString | string, aad: string): T {
  return JSON.parse(decryptString(key, value, aad)) as T;
}

/** Encrypts a key under another key. */
export function wrapKey(wrappingKey: SymmetricKey, key: SymmetricKey, aad: string): EncString {
  return encryptBytes(wrappingKey, key, aad);
}

export function unwrapKey(wrappingKey: SymmetricKey, wrapped: EncString | string, aad: string): SymmetricKey {
  return asSymmetricKey(decryptBytes(wrappingKey, wrapped, aad));
}
