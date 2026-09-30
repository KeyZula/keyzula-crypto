import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { toB64, utf8Encode } from "./encoding.ts";
import { DEFAULT_KDF, type KdfParams } from "./kdf.ts";
import { sodium } from "./sodium.ts";

/** Server-side helpers. The client auth hash is stored only as an Argon2id hash. */
const VERIFIER_OPS = 2;
const VERIFIER_MEM = 19 * 1024 * 1024;

export function hashAuthVerifier(authHash: string): string {
  return sodium().crypto_pwhash_str(authHash, VERIFIER_OPS, VERIFIER_MEM);
}

export function verifyAuthVerifier(stored: string, authHash: string): boolean {
  try {
    return sodium().crypto_pwhash_str_verify(stored, authHash);
  } catch {
    return false;
  }
}

/** Deterministic KDF parameters for unknown emails, so prelogin does not reveal registration. */
export function fakeKdfFor(email: string, serverSecret: string): KdfParams {
  const salt = hmac(sha256, utf8Encode(serverSecret), utf8Encode(`prelogin:${email.toLowerCase()}`)).slice(0, 16);
  return { algorithm: "argon2id", salt: toB64(salt), iterations: DEFAULT_KDF.iterations, memoryKiB: DEFAULT_KDF.memoryKiB };
}

/** Session token and the SHA-256 hash stored by the server. */
export function generateSessionToken(): { token: string; hash: string } {
  const token = "vs_" + toB64(sodium().randombytes_buf(32));
  return { token, hash: hashSessionToken(token) };
}

export function hashSessionToken(token: string): string {
  return toB64(sha256(utf8Encode(token)));
}
