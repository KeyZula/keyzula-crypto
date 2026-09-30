import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, fromStdB64, toStdB64, utf8Decode, utf8Encode } from "./encoding.ts";
import { CryptoError } from "./errors.ts";
import { sodium } from "./sodium.ts";

export interface SshKeyMaterial {
  /** OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) */
  privateKey: string;
  /** authorized_keys line: "ssh-ed25519 AAAA... comment" */
  publicKey: string;
  /** "SHA256:..." fingerprint, as printed by ssh-keygen -l */
  fingerprint: string;
  keyType: string;
}

const OPENSSH_MAGIC = "openssh-key-v1\0";
const PEM_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_FOOTER = "-----END OPENSSH PRIVATE KEY-----";

// SSH wire format helpers

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

function sshString(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? utf8Encode(data) : data;
  return concatBytes(u32(bytes.length), bytes);
}

class Reader {
  private offset = 0;
  constructor(private readonly buf: Uint8Array) {}
  uint32(): number {
    if (this.offset + 4 > this.buf.length) throw new CryptoError("Truncated or corrupt SSH key.", "INVALID_FORMAT");
    const v = new DataView(this.buf.buffer, this.buf.byteOffset + this.offset, 4).getUint32(0);
    this.offset += 4;
    return v;
  }
  bytes(n: number): Uint8Array {
    if (this.offset + n > this.buf.length) throw new CryptoError("Truncated or corrupt SSH key.", "INVALID_FORMAT");
    const v = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return v;
  }
  string(): Uint8Array {
    return this.bytes(this.uint32());
  }
  text(): string {
    return utf8Decode(this.string());
  }
}

export function sshFingerprint(publicKeyBlob: Uint8Array): string {
  return "SHA256:" + toStdB64(sha256(publicKeyBlob)).replace(/=+$/, "");
}

function wrapPem(body: Uint8Array): string {
  const b64 = toStdB64(body);
  const lines = b64.match(/.{1,70}/g) ?? [];
  return [PEM_HEADER, ...lines, PEM_FOOTER, ""].join("\n");
}

/** Generates an unencrypted Ed25519 key in OpenSSH format (it is stored encrypted in the vault). */
export function generateEd25519SshKey(comment = ""): SshKeyMaterial {
  const s = sodium();
  const { publicKey: pk, privateKey: sk } = s.crypto_sign_keypair();
  try {
    const keyType = "ssh-ed25519";
    const pubBlob = concatBytes(sshString(keyType), sshString(pk));
    const check = s.randombytes_buf(4);

    let privSection = concatBytes(check, check, sshString(keyType), sshString(pk), sshString(sk), sshString(comment));
    const padLen = (8 - (privSection.length % 8)) % 8;
    const padding = Uint8Array.from({ length: padLen }, (_, i) => i + 1);
    privSection = concatBytes(privSection, padding);

    const body = concatBytes(
      utf8Encode(OPENSSH_MAGIC),
      sshString("none"),
      sshString("none"),
      sshString(""),
      u32(1),
      sshString(pubBlob),
      sshString(privSection),
    );

    return {
      privateKey: wrapPem(body),
      publicKey: `${keyType} ${toStdB64(pubBlob)}${comment ? " " + comment : ""}`,
      fingerprint: sshFingerprint(pubBlob),
      keyType,
    };
  } finally {
    s.memzero(sk);
  }
}

export interface ParsedSshPrivateKey {
  keyType: string;
  publicKey: string;
  fingerprint: string;
  /** True if the key is protected by its own passphrase. */
  encrypted: boolean;
  comment?: string;
}

/**
 * Extracts the public key and fingerprint from an OpenSSH private key (also for
 * passphrase-protected keys). Returns null for legacy PEM keys.
 */
export function parseOpenSshPrivateKey(pem: string): ParsedSshPrivateKey | null {
  const text = pem.trim();
  if (!text.startsWith(PEM_HEADER) || !text.endsWith(PEM_FOOTER)) return null;
  const body = fromStdB64(text.slice(PEM_HEADER.length, text.length - PEM_FOOTER.length));
  const magic = utf8Encode(OPENSSH_MAGIC);
  if (body.length < magic.length || utf8Decode(body.subarray(0, magic.length)) !== OPENSSH_MAGIC) {
    throw new CryptoError("Invalid OpenSSH key header.", "INVALID_FORMAT");
  }
  const r = new Reader(body.subarray(magic.length));
  const cipher = r.text();
  r.text(); // kdfname
  r.string(); // kdfoptions
  const count = r.uint32();
  if (count !== 1) throw new CryptoError("Files with more than one key are not supported.", "UNSUPPORTED");
  const pubBlob = r.string();
  const keyType = new Reader(pubBlob).text();

  let comment: string | undefined;
  if (cipher === "none") {
    const priv = new Reader(r.string());
    const c1 = priv.uint32();
    const c2 = priv.uint32();
    if (c1 !== c2) throw new CryptoError("Corrupt OpenSSH key (checkint).", "INVALID_FORMAT");
    if (keyType === "ssh-ed25519") {
      priv.text();
      priv.string();
      priv.string();
      comment = priv.text() || undefined;
    }
  }

  return {
    keyType,
    publicKey: `${keyType} ${toStdB64(pubBlob)}${comment ? " " + comment : ""}`,
    fingerprint: sshFingerprint(pubBlob),
    encrypted: cipher !== "none",
    comment,
  };
}

/** Fingerprint of an authorized_keys line. */
export function fingerprintFromPublicKey(line: string): string | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  try {
    return sshFingerprint(fromStdB64(parts[1]!));
  } catch {
    return null;
  }
}
