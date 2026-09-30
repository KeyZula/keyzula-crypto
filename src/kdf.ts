import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { fromB64, toB64, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";
import { asSymmetricKey, type SymmetricKey } from "./symmetric.ts";

export interface KdfParams {
  algorithm: "argon2id";
  /** base64url, 16 bytes */
  salt: string;
  /** Argon2 time cost (t) */
  iterations: number;
  /** Argon2 memory cost in KiB (m) */
  memoryKiB: number;
}

/** Default Argon2id cost: 64 MiB, 3 iterations. */
export const DEFAULT_KDF = { iterations: 3, memoryKiB: 64 * 1024 } as const;

/**
 * Client-enforced bounds. The lower bound prevents a malicious server from downgrading
 * the KDF; the upper bound prevents it from exhausting the client.
 */
export const KDF_LIMITS = {
  minIterations: 2,
  maxIterations: 10,
  minMemoryKiB: 19 * 1024,
  maxMemoryKiB: 1024 * 1024,
} as const;

const SALT_BYTES = 16;

export function generateKdfParams(overrides: Partial<Pick<KdfParams, "iterations" | "memoryKiB">> = {}): KdfParams {
  const params: KdfParams = {
    algorithm: "argon2id",
    salt: toB64(sodium().randombytes_buf(SALT_BYTES)),
    iterations: overrides.iterations ?? DEFAULT_KDF.iterations,
    memoryKiB: overrides.memoryKiB ?? DEFAULT_KDF.memoryKiB,
  };
  assertSafeKdf(params);
  return params;
}

export function assertSafeKdf(params: KdfParams): void {
  if (params.algorithm !== "argon2id") {
    throw new CryptoError("Unsupported KDF algorithm.", "UNSUPPORTED");
  }
  const { iterations, memoryKiB } = params;
  if (
    !Number.isInteger(iterations) ||
    !Number.isInteger(memoryKiB) ||
    iterations < KDF_LIMITS.minIterations ||
    iterations > KDF_LIMITS.maxIterations ||
    memoryKiB < KDF_LIMITS.minMemoryKiB ||
    memoryKiB > KDF_LIMITS.maxMemoryKiB
  ) {
    throw new CryptoError("KDF parameters outside the allowed range.", "UNSAFE_KDF_PARAMS");
  }
  let salt: Uint8Array;
  try {
    salt = fromB64(params.salt);
  } catch {
    throw new CryptoError("Invalid KDF salt.", "INVALID_FORMAT");
  }
  if (salt.length !== SALT_BYTES) {
    throw new CryptoError("KDF salt must be 16 bytes.", "INVALID_FORMAT");
  }
}

/** NFKC so that canonically equivalent input produces the same key. */
export function normalizePassword(password: string): string {
  return password.normalize("NFKC");
}

/** Master key = Argon2id(password, salt). Deliberately expensive. */
export function deriveMasterKey(password: string, params: KdfParams): Uint8Array {
  assertSafeKdf(params);
  const s = sodium();
  return s.crypto_pwhash(
    32,
    utf8Encode(normalizePassword(password)),
    fromB64(params.salt),
    params.iterations,
    params.memoryKiB * 1024,
    s.crypto_pwhash_ALG_ARGON2ID13,
  );
}

const INFO_AUTH = "vault/v1/auth-hash";
const INFO_KEK = "vault/v1/key-encryption-key";

/** Domain-separated subkey derivation (HKDF-SHA256). */
export function hkdfExpand(ikm: Uint8Array, info: string, length = 32): Uint8Array {
  return hkdf(sha256, ikm, undefined, utf8Encode(info), length);
}

export interface PasswordDerivation {
  /** Login verifier sent to the server. Reveals nothing about the key-encryption key. */
  authHash: string;
  /** Wraps the user key. Never leaves the client. */
  kek: SymmetricKey;
}

export function deriveFromPassword(password: string, params: KdfParams): PasswordDerivation {
  const masterKey = deriveMasterKey(password, params);
  try {
    return {
      authHash: toB64(hkdfExpand(masterKey, INFO_AUTH)),
      kek: asSymmetricKey(hkdfExpand(masterKey, INFO_KEK)),
    };
  } finally {
    sodium().memzero(masterKey);
  }
}
