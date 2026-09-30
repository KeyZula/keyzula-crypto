import { AAD } from "./account.ts";
import { decryptJson, encryptJson, generateSymmetricKey, unwrapKey, wrapKey, type EncString, type SymmetricKey } from "./symmetric.ts";

export interface EncryptedItemPayload {
  /** Per-item key, wrapped with the owner key (user key or collection key). */
  key: EncString;
  /** Entire item content as one ciphertext. */
  data: EncString;
}

/** Encrypts an item under its own random key. Both ciphertexts are bound to the item id. */
export function encryptItem(ownerKey: SymmetricKey, itemId: string, data: unknown, existingItemKey?: SymmetricKey): EncryptedItemPayload {
  const itemKey = existingItemKey ?? generateSymmetricKey();
  return {
    key: wrapKey(ownerKey, itemKey, AAD.itemKey(itemId)),
    data: encryptJson(itemKey, data, AAD.itemData(itemId)),
  };
}

export function decryptItem<T>(ownerKey: SymmetricKey, itemId: string, payload: { key: string; data: string }): { itemKey: SymmetricKey; data: T } {
  const itemKey = unwrapKey(ownerKey, payload.key, AAD.itemKey(itemId));
  return { itemKey, data: decryptJson<T>(itemKey, payload.data, AAD.itemData(itemId)) };
}

/** Re-wraps an item key when the item moves to another owner. */
export function rewrapItemKey(fromKey: SymmetricKey, toKey: SymmetricKey, itemId: string, wrappedKey: string): EncString {
  const itemKey = unwrapKey(fromKey, wrappedKey, AAD.itemKey(itemId));
  return wrapKey(toKey, itemKey, AAD.itemKey(itemId));
}
