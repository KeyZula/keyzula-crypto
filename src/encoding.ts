import { sodium } from "./sodium.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8Encode(value: string): Uint8Array {
  return encoder.encode(value);
}

export function utf8Decode(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Base64url without padding. */
export function toB64(bytes: Uint8Array): string {
  const s = sodium();
  return s.to_base64(bytes, s.base64_variants.URLSAFE_NO_PADDING);
}

export function fromB64(value: string): Uint8Array {
  const s = sodium();
  return s.from_base64(value, s.base64_variants.URLSAFE_NO_PADDING);
}

/** Standard padded base64 (used for OpenSSH formats). */
export function toStdB64(bytes: Uint8Array): string {
  const s = sodium();
  return s.to_base64(bytes, s.base64_variants.ORIGINAL);
}

export function fromStdB64(value: string): Uint8Array {
  const s = sodium();
  return s.from_base64(value.replace(/\s+/g, ""), s.base64_variants.ORIGINAL);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time comparison. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return sodium().memcmp(a, b);
}

export function wipe(bytes: Uint8Array | undefined | null): void {
  if (bytes) sodium().memzero(bytes);
}
