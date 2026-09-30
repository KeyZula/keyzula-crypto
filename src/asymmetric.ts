import { concatBytes, fromB64, toB64, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";
import { asSymmetricKey, type SymmetricKey } from "./symmetric.ts";

export interface KeyPair {
  /** X25519 public key (base64url) */
  publicKey: string;
  /** X25519 private key (raw bytes) */
  privateKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const kp = sodium().crypto_box_keypair();
  return { publicKey: toB64(kp.publicKey), privateKey: kp.privateKey };
}

function decodePublicKey(publicKey: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = fromB64(publicKey);
  } catch {
    throw new CryptoError("Invalid public key.", "INVALID_KEY");
  }
  if (bytes.length !== sodium().crypto_box_PUBLICKEYBYTES) {
    throw new CryptoError("Invalid public key length.", "INVALID_KEY");
  }
  return bytes;
}

/** Encrypts a symmetric key to a recipient public key (libsodium sealed box). */
export function sealKey(key: SymmetricKey, recipientPublicKey: string): string {
  return toB64(sodium().crypto_box_seal(key, decodePublicKey(recipientPublicKey)));
}

export function openSealedKey(sealed: string, publicKey: string, privateKey: Uint8Array): SymmetricKey {
  try {
    return asSymmetricKey(sodium().crypto_box_seal_open(fromB64(sealed), decodePublicKey(publicKey), privateKey));
  } catch (err) {
    if (err instanceof CryptoError) throw err;
    throw new CryptoError("Could not open sealed key.", "DECRYPT_FAILED");
  }
}

/**
 * Human-comparable fingerprint of (account id, public key): six groups of five digits
 * derived from BLAKE2b-256. Compared out of band to detect key substitution.
 */
export function publicKeyFingerprint(publicKey: string, accountId: string): string {
  const digest = sodium().crypto_generichash(
    32,
    concatBytes(utf8Encode("vault/v1/fingerprint\0"), utf8Encode(accountId.toLowerCase()), decodePublicKey(publicKey)),
    null,
  );
  const groups: string[] = [];
  for (let i = 0; i < 6; i++) {
    const n = ((digest[i * 4]! << 24) | (digest[i * 4 + 1]! << 16) | (digest[i * 4 + 2]! << 8) | digest[i * 4 + 3]!) >>> 0;
    groups.push(String(n % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}
