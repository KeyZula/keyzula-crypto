import { beforeAll, describe, expect, it } from "vitest";
import { CryptoError, createAttachment, decryptAttachment, encryptAttachment, encryptedAttachmentSize, generateSymmetricKey, initCrypto, openAttachment, randomBytes } from "../src/index.ts";

beforeAll(async () => {
  await initCrypto();
});

const ID = "7d8a6c3e-0f5b-4b8e-9c61-2d8f4e1a0b11";
const MiB = 1024 * 1024;

describe("attachments", () => {
  it("opens key and metadata with the item key", () => {
    const itemKey = generateSymmetricKey();
    const created = createAttachment(itemKey, ID, { name: "passport.pdf", type: "application/pdf" });
    const opened = openAttachment(itemKey, ID, created);
    expect(opened.meta).toEqual({ name: "passport.pdf", type: "application/pdf" });
    expect(opened.attachmentKey).toEqual(created.attachmentKey);
    expect(() => openAttachment(generateSymmetricKey(), ID, created)).toThrow(CryptoError);
  });

  it.each([0, 1, 1000, MiB - 1, MiB, MiB + 1, 3 * MiB + 17])("round-trips a %i byte file", (size) => {
    const key = generateSymmetricKey();
    const plain = size ? randomBytes(size) : new Uint8Array();
    const enc = encryptAttachment(key, ID, plain);
    expect(enc.length).toBe(encryptedAttachmentSize(size));
    expect(Buffer.compare(decryptAttachment(key, ID, enc), plain)).toBe(0);
  });

  it("rejects truncated, modified or foreign content", () => {
    const key = generateSymmetricKey();
    const enc = encryptAttachment(key, ID, randomBytes(2 * MiB + 5));
    // Dropping the last chunk fails: the previous chunk is not marked final.
    expect(() => decryptAttachment(key, ID, enc.subarray(0, 4 + MiB + 40))).toThrow(CryptoError);
    const flipped = enc.slice();
    flipped[100] = flipped[100]! ^ 1;
    expect(() => decryptAttachment(key, ID, flipped)).toThrow(CryptoError);
    expect(() => decryptAttachment(key, "00000000-0000-0000-0000-000000000000", enc)).toThrow(CryptoError);
    expect(() => decryptAttachment(generateSymmetricKey(), ID, enc)).toThrow(CryptoError);
  });
});
