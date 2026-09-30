import { concatBytes, fromB64, toB64, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";
import { SYMMETRIC_KEY_BYTES, asSymmetricKey, decryptJson, encryptJson, generateSymmetricKey, unwrapKey, wrapKey, type EncString, type SymmetricKey } from "./symmetric.ts";

/**
 * Send: content is encrypted with a random link key carried only in the URL fragment.
 * The server stores a copy of the link key wrapped with the owner's user key.
 */
const AAD_SEND_KEY = (id: string) => `vault/v1/send-key:${id}`;
const AAD_SEND_DATA = (id: string) => `vault/v1/send:${id}`;

export const createSendKey = (): SymmetricKey => generateSymmetricKey();

/** URL fragment: 32 bytes as 43 base64url characters. */
export const sendKeyToString = (key: SymmetricKey): string => toB64(key);

export function sendKeyFromString(value: string): SymmetricKey {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new CryptoError("Invalid link key.", "INVALID_KEY");
  const bytes = fromB64(value);
  if (bytes.length !== SYMMETRIC_KEY_BYTES) throw new CryptoError("Invalid link key.", "INVALID_KEY");
  return asSymmetricKey(bytes);
}

export const wrapSendKey = (userKey: SymmetricKey, key: SymmetricKey, id: string): EncString => wrapKey(userKey, key, AAD_SEND_KEY(id));
export const unwrapSendKey = (userKey: SymmetricKey, wrapped: string, id: string): SymmetricKey => unwrapKey(userKey, wrapped, AAD_SEND_KEY(id));

export const encryptSendData = (key: SymmetricKey, id: string, data: unknown): EncString => encryptJson(key, data, AAD_SEND_DATA(id));
export const decryptSendData = (key: SymmetricKey, id: string, value: string): unknown => decryptJson<unknown>(key, value, AAD_SEND_DATA(id));

/**
 * Send password verifier: BLAKE2b keyed with the link key. Without the link key the
 * verifier cannot be used to test password guesses.
 */
export function sendPasswordVerifier(password: string, key: SymmetricKey): string {
  return toB64(sodium().crypto_generichash(32, concatBytes(utf8Encode("vault/v1/send-password\0"), utf8Encode(password.normalize("NFKC"))), key));
}
