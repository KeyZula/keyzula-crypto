import { AAD } from "./account.ts";
import { generateKeyPair, openSealedKey, sealKey, type KeyPair } from "./asymmetric.ts";
import { fromB64, toB64 } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { SYMMETRIC_KEY_BYTES, asSymmetricKey, encryptBytes, generateSymmetricKey, randomBytes, unwrapKey, wrapKey, type EncString, type SymmetricKey } from "./symmetric.ts";
import type { UnlockedKeys } from "./account.ts";

/**
 * SSO accounts without a master password. The user key is recovered via:
 *  - trusted device: wrapped with a random device key that stays on the device
 *  - device approval: sealed to the new device's ephemeral public key
 *  - account recovery: sealed to the organization public key (admins only)
 */

/** New account without a master password. Keys are generated on the device. */
export function createPasswordlessAccount(): { userKey: SymmetricKey; publicKey: string; privateKey: Uint8Array; protectedPrivateKey: EncString } {
  const userKey = generateSymmetricKey();
  const { publicKey, privateKey } = generateKeyPair();
  return { userKey, publicKey, privateKey, protectedPrivateKey: encryptBytes(userKey, privateKey, AAD.privateKey) };
}

// Trusted devices

export const createDeviceKey = (): SymmetricKey => generateSymmetricKey();
export const deviceKeyToString = (key: SymmetricKey): string => toB64(key);
export function deviceKeyFromString(value: string): SymmetricKey {
  const bytes = fromB64(value);
  if (bytes.length !== SYMMETRIC_KEY_BYTES) throw new CryptoError("Invalid device key.", "INVALID_KEY");
  return asSymmetricKey(bytes);
}
export const wrapUserKeyForDevice = (deviceKey: SymmetricKey, userKey: SymmetricKey): EncString => wrapKey(deviceKey, userKey, AAD.deviceUserKey);
export const unwrapUserKeyForDevice = (deviceKey: SymmetricKey, wrapped: string): SymmetricKey => unwrapKey(deviceKey, wrapped, AAD.deviceUserKey);

// Organization keys and account recovery

export const createOrgKeyPair = (): KeyPair => generateKeyPair();
/** Seals the organization private key to an admin's public key. */
export const sealOrgPrivateKey = (orgPrivateKey: Uint8Array, adminPublicKey: string): string => sealKey(asSymmetricKey(orgPrivateKey), adminPublicKey);
export const openOrgPrivateKey = (sealed: string, admin: Pick<UnlockedKeys, "publicKey" | "privateKey">): Uint8Array =>
  openSealedKey(sealed, admin.publicKey, admin.privateKey);

/** User key sealed to the organization public key (admin recovery). */
export const createRecoveryKey = (userKey: SymmetricKey, orgPublicKey: string): string => sealKey(userKey, orgPublicKey);
export const openRecoveryKey = (recoveryKey: string, orgPublicKey: string, orgPrivateKey: Uint8Array): SymmetricKey =>
  openSealedKey(recoveryKey, orgPublicKey, orgPrivateKey);

// Device approval

/** Ephemeral key pair for a pending approval request. Kept in memory only. */
export const createApprovalKeyPair = (): KeyPair => generateKeyPair();
export const sealUserKeyForDevice = (userKey: SymmetricKey, requestPublicKey: string): string => sealKey(userKey, requestPublicKey);
export const openApprovedUserKey = (sealed: string, request: KeyPair): SymmetricKey => openSealedKey(sealed, request.publicKey, request.privateKey);

// Key-based re-authentication for accounts without a master password

/** Server: random challenge sealed to the account public key, and the expected answer. */
export function createKeyProof(publicKey: string): { sealed: string; answer: string } {
  const secret = asSymmetricKey(randomBytes(SYMMETRIC_KEY_BYTES));
  return { sealed: sealKey(secret, publicKey), answer: toB64(secret) };
}
/** Client: answers the challenge with the unlocked private key. */
export const answerKeyProof = (sealed: string, keys: Pick<UnlockedKeys, "publicKey" | "privateKey">): string => toB64(openSealedKey(sealed, keys.publicKey, keys.privateKey));
