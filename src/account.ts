import { generateKeyPair } from "./asymmetric.ts";
import { concatBytes, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { deriveFromPassword, generateKdfParams, hkdfExpand, type KdfParams } from "./kdf.ts";
import { asSymmetricKey, decryptBytes, encryptBytes, generateSymmetricKey, unwrapKey, wrapKey, type EncString, type SymmetricKey } from "./symmetric.ts";

export const AAD = {
  userKey: "vault/v1/user-key",
  privateKey: "vault/v1/private-key",
  itemKey: (id: string) => `vault/v1/item-key:${id}`,
  itemData: (id: string) => `vault/v1/item:${id}`,
  folderName: (id: string) => `vault/v1/folder:${id}`,
  collectionName: (id: string) => `vault/v1/collection:${id}`,
  pinUserKey: "vault/v1/pin-user-key",
  reloadUserKey: "vault/v1/reload-user-key",
  passkeyUserKey: "vault/v1/passkey-user-key",
  extensionToken: "vault/v1/extension-token",
  deviceUserKey: "vault/v1/device-user-key",
} as const;

/** Key material uploaded at registration. Contains only public or encrypted values. */
export interface AccountKeyMaterial {
  kdf: KdfParams;
  authHash: string;
  protectedUserKey: EncString;
  publicKey: string;
  protectedPrivateKey: EncString;
}

/** Keys held in memory while the vault is unlocked. */
export interface UnlockedKeys {
  userKey: SymmetricKey;
  publicKey: string;
  privateKey: Uint8Array;
}

export function createAccount(password: string, kdfOverrides?: Partial<Pick<KdfParams, "iterations" | "memoryKiB">>): {
  material: AccountKeyMaterial;
  keys: UnlockedKeys;
} {
  const kdf = generateKdfParams(kdfOverrides);
  const { authHash, kek } = deriveFromPassword(password, kdf);
  const userKey = generateSymmetricKey();
  const { publicKey, privateKey } = generateKeyPair();
  return {
    material: {
      kdf,
      authHash,
      protectedUserKey: wrapKey(kek, userKey, AAD.userKey),
      publicKey,
      protectedPrivateKey: encryptBytes(userKey, privateKey, AAD.privateKey),
    },
    keys: { userKey, publicKey, privateKey },
  };
}

export function unlockKeys(
  kek: SymmetricKey,
  account: { protectedUserKey: string | null; publicKey: string; protectedPrivateKey: string },
): UnlockedKeys {
  if (!account.protectedUserKey) throw new CryptoError("This account has no master password.", "INVALID_KEY");
  const userKey = unwrapKey(kek, account.protectedUserKey, AAD.userKey);
  const privateKey = decryptBytes(userKey, account.protectedPrivateKey, AAD.privateKey);
  return { userKey, publicKey: account.publicKey, privateKey };
}

/** Password change: the user key is unchanged and re-wrapped under a new KEK. */
export function rewrapForNewPassword(
  userKey: SymmetricKey,
  newPassword: string,
  kdfOverrides?: Partial<Pick<KdfParams, "iterations" | "memoryKiB">>,
): { kdf: KdfParams; authHash: string; protectedUserKey: EncString } {
  const kdf = generateKdfParams(kdfOverrides);
  const { authHash, kek } = deriveFromPassword(newPassword, kdf);
  return { kdf, authHash, protectedUserKey: wrapKey(kek, userKey, AAD.userKey) };
}

/** Restores the unlocked key set from a user key (PIN, biometric or reload unlock). */
export function keysFromUserKey(userKey: SymmetricKey, account: { publicKey: string; protectedPrivateKey: string }): UnlockedKeys {
  const privateKey = decryptBytes(userKey, account.protectedPrivateKey, AAD.privateKey);
  return { userKey, publicKey: account.publicKey, privateKey };
}

/**
 * Unlock key = HKDF(localSecret || serverShare). The server releases its share only to an
 * authorized session, so a locally stored wrapped key cannot be attacked offline on its own.
 */
export function deriveUnlockKey(serverShare: Uint8Array, localSecret: Uint8Array = new Uint8Array()): SymmetricKey {
  if (serverShare.length < 32) throw new CryptoError("Server share too short.", "INVALID_FORMAT");
  return asSymmetricKey(hkdfExpand(concatBytes(localSecret, serverShare), "vault/v1/unlock-key"));
}

/** Fixed WebAuthn PRF input. The output is specific to each credential. */
export const PASSKEY_PRF_SALT = utf8Encode("KeyZula passkey login v1".padEnd(32, "\u0000"));

/** Wrapping key derived from a passkey PRF output. The PRF output never leaves the client. */
export function deriveKeyFromPrf(prfOutput: Uint8Array): SymmetricKey {
  if (prfOutput.length < 32) throw new CryptoError("PRF output too short.", "INVALID_FORMAT");
  return asSymmetricKey(hkdfExpand(prfOutput, "vault/v1/passkey-key"));
}
