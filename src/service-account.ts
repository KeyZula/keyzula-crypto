import { sha256 } from "@noble/hashes/sha2.js";
import { generateKeyPair, openSealedKey } from "./asymmetric.ts";
import { fromB64, toB64 } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { hkdfExpand } from "./kdf.ts";
import { sodium } from "./sodium.ts";
import { SYMMETRIC_KEY_BYTES, asSymmetricKey, decryptBytes, encryptBytes, randomBytes, type EncString, type SymmetricKey } from "./symmetric.ts";

/**
 * Service account access tokens (machine identities).
 *
 * Each token has its own X25519 key pair. The 256-bit token secret is split with HKDF into:
 *  - auth: presented to the server, which stores only SHA-256(auth)
 *  - wrap: encrypts the token private key; never sent to the server
 * Collection keys are sealed to the token public key.
 *
 * Token:      kzsa_1_<service account id>_<secret, base64url>
 * Credential: kzsa_auth_<service account id>_<auth key, base64url>  (Authorization: Bearer)
 */

export const SERVICE_TOKEN_VERSION = 1;
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
export const SERVICE_TOKEN_PATTERN = new RegExp(`^kzsa_${SERVICE_TOKEN_VERSION}_(${UUID})_([A-Za-z0-9_-]{43})$`);
export const SERVICE_AUTH_PATTERN = new RegExp(`^kzsa_auth_(${UUID})_([A-Za-z0-9_-]{43})$`);

const INFO_AUTH = "keyzula/v1/service-token-auth";
const INFO_WRAP = "keyzula/v1/service-token-wrap";
const aadPrivateKey = (serviceAccountId: string, tokenId: string) => `keyzula/v1/service-token-private-key:${serviceAccountId}:${tokenId}`;

export interface ParsedServiceToken {
  serviceAccountId: string;
  secret: Uint8Array;
}

/** Created on the admin's client. `token` is shown once and never sent to the server. */
export interface CreatedServiceToken {
  token: string;
  publicKey: string;
  /** Needed only to seal collection keys for this token; wipe after use. */
  privateKey: Uint8Array;
  encryptedPrivateKey: EncString;
  /** SHA-256 of the auth key (base64url) */
  verifier: string;
}

function subKeys(secret: Uint8Array): { auth: Uint8Array; wrap: SymmetricKey } {
  if (secret.length !== SYMMETRIC_KEY_BYTES) throw new CryptoError("Invalid service token.", "INVALID_KEY");
  return { auth: hkdfExpand(secret, INFO_AUTH), wrap: asSymmetricKey(hkdfExpand(secret, INFO_WRAP)) };
}

/** Stored verifier for an auth key. */
export function serviceAuthVerifier(authKey: Uint8Array): string {
  return toB64(sha256(authKey));
}

export function createServiceToken(serviceAccountId: string, tokenId: string): CreatedServiceToken {
  const secret = randomBytes(SYMMETRIC_KEY_BYTES);
  const { auth, wrap } = subKeys(secret);
  const { publicKey, privateKey } = generateKeyPair();
  const token = `kzsa_${SERVICE_TOKEN_VERSION}_${serviceAccountId.toLowerCase()}_${toB64(secret)}`;
  const result: CreatedServiceToken = {
    token,
    publicKey,
    privateKey,
    encryptedPrivateKey: encryptBytes(wrap, privateKey, aadPrivateKey(serviceAccountId.toLowerCase(), tokenId.toLowerCase())),
    verifier: serviceAuthVerifier(auth),
  };
  sodium().memzero(secret);
  sodium().memzero(wrap);
  return result;
}

export function parseServiceToken(token: string): ParsedServiceToken {
  const m = SERVICE_TOKEN_PATTERN.exec(token.trim());
  if (!m) throw new CryptoError("Unrecognized service token format (expected kzsa_1_...).", "INVALID_FORMAT");
  const secret = fromB64(m[2]!);
  if (secret.length !== SYMMETRIC_KEY_BYTES) throw new CryptoError("Corrupt service token.", "INVALID_FORMAT");
  return { serviceAccountId: m[1]!, secret };
}

/** Credential sent to the server: the derived auth key, not the token secret. */
export function serviceAuthCredential(parsed: ParsedServiceToken): string {
  return `kzsa_auth_${parsed.serviceAccountId}_${toB64(subKeys(parsed.secret).auth)}`;
}

/** Server: parses a credential and computes its verifier. Returns null if malformed. */
export function parseServiceAuthCredential(credential: string): { serviceAccountId: string; verifier: string } | null {
  const m = SERVICE_AUTH_PATTERN.exec(credential);
  if (!m) return null;
  let auth: Uint8Array;
  try {
    auth = fromB64(m[2]!);
  } catch {
    return null;
  }
  if (auth.length !== 32) return null;
  return { serviceAccountId: m[1]!, verifier: serviceAuthVerifier(auth) };
}

/** Client: decrypts the token private key. The public key is recomputed locally, not taken from the server. */
export function openServiceTokenKeys(
  parsed: ParsedServiceToken,
  tokenId: string,
  encryptedPrivateKey: string,
): { publicKey: string; privateKey: Uint8Array } {
  const { wrap } = subKeys(parsed.secret);
  try {
    const privateKey = decryptBytes(wrap, encryptedPrivateKey, aadPrivateKey(parsed.serviceAccountId, tokenId.toLowerCase()));
    return { publicKey: toB64(sodium().crypto_scalarmult_base(privateKey)), privateKey };
  } finally {
    sodium().memzero(wrap);
  }
}

/** Opens a collection key sealed to the token. */
export function openServiceCollectionKey(sealedKey: string, keys: { publicKey: string; privateKey: Uint8Array }): SymmetricKey {
  return openSealedKey(sealedKey, keys.publicKey, keys.privateKey);
}
