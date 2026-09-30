import { concatBytes, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";
import { decryptJson, encryptJson, generateSymmetricKey, unwrapKey, wrapKey, type EncString, type SymmetricKey } from "./symmetric.ts";

/**
 * Attachments. Each attachment has its own random key, wrapped with the item key.
 *
 * Format: "KZA1" || chunk*, chunk = nonce (24) || XChaCha20-Poly1305(plaintext <= 1 MiB).
 * Chunk AAD = "vault/v1/attachment:<id>\0" || u32be(index) || u8(final). This prevents
 * reordering, truncation and mixing chunks between attachments.
 */
const MAGIC = utf8Encode("KZA1");
const CHUNK = 1024 * 1024;
const NONCE = 24;
const TAG = 16;

const AAD_KEY = (id: string) => `vault/v1/attachment-key:${id}`;
const AAD_META = (id: string) => `vault/v1/attachment-meta:${id}`;

export interface AttachmentMeta {
  name: string;
  type: string;
}

function chunkAad(id: string, index: number, final: boolean): Uint8Array {
  const tail = new Uint8Array(5);
  new DataView(tail.buffer).setUint32(0, index);
  tail[4] = final ? 1 : 0;
  return concatBytes(utf8Encode(`vault/v1/attachment:${id}\0`), tail);
}

/** Ciphertext size for a given plaintext size. */
export function encryptedAttachmentSize(plainSize: number): number {
  const chunks = Math.max(1, Math.ceil(plainSize / CHUNK));
  return MAGIC.length + plainSize + chunks * (NONCE + TAG);
}

export function createAttachment(itemKey: SymmetricKey, id: string, meta: AttachmentMeta): { attachmentKey: SymmetricKey; key: EncString; meta: EncString } {
  const attachmentKey = generateSymmetricKey();
  return { attachmentKey, key: wrapKey(itemKey, attachmentKey, AAD_KEY(id)), meta: encryptJson(attachmentKey, meta, AAD_META(id)) };
}

export function openAttachment(itemKey: SymmetricKey, id: string, record: { key: string; meta: string }): { attachmentKey: SymmetricKey; meta: AttachmentMeta } {
  const attachmentKey = unwrapKey(itemKey, record.key, AAD_KEY(id));
  return { attachmentKey, meta: decryptJson<AttachmentMeta>(attachmentKey, record.meta, AAD_META(id)) };
}

export function encryptAttachment(attachmentKey: SymmetricKey, id: string, plain: Uint8Array): Uint8Array {
  const s = sodium();
  const out = new Uint8Array(encryptedAttachmentSize(plain.length));
  out.set(MAGIC, 0);
  let offset = MAGIC.length;
  const chunks = Math.max(1, Math.ceil(plain.length / CHUNK));
  for (let i = 0; i < chunks; i++) {
    const part = plain.subarray(i * CHUNK, Math.min(plain.length, (i + 1) * CHUNK));
    const nonce = s.randombytes_buf(NONCE);
    const sealed = s.crypto_aead_xchacha20poly1305_ietf_encrypt(part, chunkAad(id, i, i === chunks - 1), null, nonce, attachmentKey);
    out.set(nonce, offset);
    out.set(sealed, offset + NONCE);
    offset += NONCE + sealed.length;
  }
  return out;
}

export function decryptAttachment(attachmentKey: SymmetricKey, id: string, data: Uint8Array): Uint8Array {
  const s = sodium();
  if (data.length < MAGIC.length + NONCE + TAG || !MAGIC.every((b, i) => data[i] === b)) {
    throw new CryptoError("Unrecognized file format.", "INVALID_FORMAT");
  }
  const body = data.length - MAGIC.length;
  const full = CHUNK + NONCE + TAG;
  const chunks = Math.max(1, Math.ceil(body / full));
  const plainSize = body - chunks * (NONCE + TAG);
  if (plainSize < 0) throw new CryptoError("Corrupt file.", "INVALID_FORMAT");
  const out = new Uint8Array(plainSize);
  let offset = MAGIC.length;
  let written = 0;
  for (let i = 0; i < chunks; i++) {
    const end = Math.min(data.length, offset + full);
    const nonce = data.subarray(offset, offset + NONCE);
    const sealed = data.subarray(offset + NONCE, end);
    let part: Uint8Array;
    try {
      part = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, sealed, chunkAad(id, i, i === chunks - 1), nonce, attachmentKey);
    } catch {
      throw new CryptoError("Decryption failed: wrong key or modified file.", "DECRYPT_FAILED");
    }
    out.set(part, written);
    written += part.length;
    offset = end;
  }
  return out;
}
