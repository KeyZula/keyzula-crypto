export { initCrypto } from "./sodium.ts";
export { CryptoError } from "./errors.ts";
export { toB64, fromB64, utf8Encode, utf8Decode, bytesEqual, wipe } from "./encoding.ts";
export {
  type SymmetricKey,
  type EncString,
  SYMMETRIC_KEY_BYTES,
  asSymmetricKey,
  generateSymmetricKey,
  randomBytes,
  isEncString,
  encryptBytes,
  decryptBytes,
  encryptString,
  decryptString,
  encryptJson,
  decryptJson,
  wrapKey,
  unwrapKey,
} from "./symmetric.ts";
export {
  type KdfParams,
  type PasswordDerivation,
  DEFAULT_KDF,
  KDF_LIMITS,
  generateKdfParams,
  assertSafeKdf,
  deriveFromPassword,
} from "./kdf.ts";
export { type KeyPair, generateKeyPair, sealKey, openSealedKey, publicKeyFingerprint } from "./asymmetric.ts";
export { AAD, type AccountKeyMaterial, type UnlockedKeys, createAccount, unlockKeys, rewrapForNewPassword, keysFromUserKey, deriveUnlockKey, deriveKeyFromPrf, PASSKEY_PRF_SALT } from "./account.ts";
export { type EncryptedItemPayload, encryptItem, decryptItem, rewrapItemKey } from "./items.ts";
export {
  createPasswordlessAccount,
  createDeviceKey,
  deviceKeyToString,
  deviceKeyFromString,
  wrapUserKeyForDevice,
  unwrapUserKeyForDevice,
  createOrgKeyPair,
  sealOrgPrivateKey,
  openOrgPrivateKey,
  createRecoveryKey,
  openRecoveryKey,
  createApprovalKeyPair,
  sealUserKeyForDevice,
  openApprovedUserKey,
  createKeyProof,
  answerKeyProof,
} from "./sso.ts";
export {
  createSendKey,
  sendKeyToString,
  sendKeyFromString,
  wrapSendKey,
  unwrapSendKey,
  encryptSendData,
  decryptSendData,
  sendPasswordVerifier,
} from "./send.ts";
export {
  type PasswordOptions,
  type PassphraseOptions,
  type StrengthResult,
  DEFAULT_PASSWORD_OPTIONS,
  DEFAULT_PASSPHRASE_OPTIONS,
  generatePassword,
  generatePassphrase,
  passphraseEntropyBits,
  estimateStrength,
} from "./generator.ts";
export { EFF_LARGE_WORDLIST } from "./wordlist.ts";
export {
  type SshKeyMaterial,
  type ParsedSshPrivateKey,
  generateEd25519SshKey,
  parseOpenSshPrivateKey,
  fingerprintFromPublicKey,
} from "./ssh.ts";
export { hashAuthVerifier, verifyAuthVerifier, fakeKdfFor, generateSessionToken, hashSessionToken } from "./server.ts";
export {
  type AttachmentMeta,
  encryptedAttachmentSize,
  createAttachment,
  openAttachment,
  encryptAttachment,
  decryptAttachment,
} from "./attachments.ts";
export {
  type ParsedServiceToken,
  type CreatedServiceToken,
  SERVICE_TOKEN_VERSION,
  SERVICE_TOKEN_PATTERN,
  SERVICE_AUTH_PATTERN,
  createServiceToken,
  parseServiceToken,
  serviceAuthCredential,
  parseServiceAuthCredential,
  serviceAuthVerifier,
  openServiceTokenKeys,
  openServiceCollectionKey,
} from "./service-account.ts";
