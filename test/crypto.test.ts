import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  AAD,
  CryptoError,
  createAccount,
  decryptItem,
  decryptString,
  deriveFromPassword,
  encryptItem,
  encryptString,
  estimateStrength,
  fingerprintFromPublicKey,
  generateEd25519SshKey,
  generateKdfParams,
  generateKeyPair,
  generatePassword,
  generatePassphrase,
  passphraseEntropyBits,
  EFF_LARGE_WORDLIST,
  generateSymmetricKey,
  initCrypto,
  isEncString,
  openSealedKey,
  parseOpenSshPrivateKey,
  publicKeyFingerprint,
  rewrapForNewPassword,
  rewrapItemKey,
  sealKey,
  unlockKeys,
  assertSafeKdf,
} from "../src/index.ts";

// Lowest allowed KDF cost, for test speed.
const FAST_KDF = { iterations: 2, memoryKiB: 19 * 1024 };

beforeAll(async () => {
  await initCrypto();
});

function expectCode(fn: () => unknown, code: CryptoError["code"]): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(CryptoError);
    expect((err as CryptoError).code).toBe(code);
    return;
  }
  throw new Error("expected CryptoError " + code);
}

describe("symmetric encryption", () => {
  it("encrypts and decrypts", () => {
    const key = generateSymmetricKey();
    const enc = encryptString(key, "secret value \u00e9\u00df\u2603", "ctx");
    expect(isEncString(enc)).toBe(true);
    expect(decryptString(key, enc, "ctx")).toBe("secret value \u00e9\u00df\u2603");
  });

  it("uses a fresh nonce for every encryption", () => {
    const key = generateSymmetricKey();
    expect(encryptString(key, "x", "c")).not.toBe(encryptString(key, "x", "c"));
  });

  it("rejects the wrong key", () => {
    const enc = encryptString(generateSymmetricKey(), "x", "c");
    expect(() => decryptString(generateSymmetricKey(), enc, "c")).toThrow(CryptoError);
  });

  it("rejects a different AAD context", () => {
    const key = generateSymmetricKey();
    const enc = encryptString(key, "x", AAD.itemData("a"));
    expect(() => decryptString(key, enc, AAD.itemData("b"))).toThrow(CryptoError);
  });

  it("rejects modified ciphertext", () => {
    const key = generateSymmetricKey();
    const enc = encryptString(key, "hello world", "c");
    const [v, n, ct] = enc.split(".");
    const flipped = ct!.slice(0, -2) + (ct!.at(-2) === "A" ? "B" : "A") + ct!.at(-1);
    expect(() => decryptString(key, `${v}.${n}.${flipped}`, "c")).toThrow(CryptoError);
  });

  it("rejects an unknown format", () => {
    expectCode(() => decryptString(generateSymmetricKey(), "v2.abc.def", "c"), "INVALID_FORMAT");
  });
});

describe("account keys", () => {
  it("recovers the user key on login", () => {
    const { material, keys } = createAccount("correct horse battery staple 42!", FAST_KDF);
    const login = deriveFromPassword("correct horse battery staple 42!", material.kdf);
    expect(login.authHash).toBe(material.authHash);
    const unlocked = unlockKeys(login.kek, material);
    expect(Buffer.from(unlocked.userKey)).toEqual(Buffer.from(keys.userKey));
    expect(Buffer.from(unlocked.privateKey)).toEqual(Buffer.from(keys.privateKey));
  });

  it("a wrong password yields a different auth hash and cannot unlock", () => {
    const { material } = createAccount("right-password", FAST_KDF);
    const wrong = deriveFromPassword("wrong-password", material.kdf);
    expect(wrong.authHash).not.toBe(material.authHash);
    expect(() => unlockKeys(wrong.kek, material)).toThrow(CryptoError);
  });

  it("auth hash and KEK are domain-separated", () => {
    const { material } = createAccount("sifre", FAST_KDF);
    const d = deriveFromPassword("sifre", material.kdf);
    expect(d.authHash).not.toBe(Buffer.from(d.kek).toString("base64url"));
  });

  it("normalizes composed and decomposed Unicode input", () => {
    const kdf = generateKdfParams(FAST_KDF);
    const composed = "şifre".normalize("NFC");
    const decomposed = "şifre".normalize("NFD");
    expect(composed).not.toBe(decomposed);
    expect(deriveFromPassword(composed, kdf).authHash).toBe(deriveFromPassword(decomposed, kdf).authHash);
  });

  it("password change keeps the user key", () => {
    const { material, keys } = createAccount("old", FAST_KDF);
    const changed = rewrapForNewPassword(keys.userKey, "new", FAST_KDF);
    const { kek } = deriveFromPassword("new", changed.kdf);
    const unlocked = unlockKeys(kek, { ...material, protectedUserKey: changed.protectedUserKey });
    expect(Buffer.from(unlocked.userKey)).toEqual(Buffer.from(keys.userKey));
    expect(changed.kdf.salt).not.toBe(material.kdf.salt);
  });

  it("rejects unsafe KDF parameters", () => {
    const kdf = generateKdfParams(FAST_KDF);
    expectCode(() => assertSafeKdf({ ...kdf, iterations: 1 }), "UNSAFE_KDF_PARAMS");
    expectCode(() => assertSafeKdf({ ...kdf, memoryKiB: 1024 }), "UNSAFE_KDF_PARAMS");
    expectCode(() => assertSafeKdf({ ...kdf, memoryKiB: 8 * 1024 * 1024 }), "UNSAFE_KDF_PARAMS");
    expect(() => assertSafeKdf({ ...kdf, salt: "kisa" })).toThrow();
  });
});

describe("item encryption", () => {
  it("encrypts with a per-item key and moves between owners", () => {
    const personal = generateSymmetricKey();
    const collection = generateSymmetricKey();
    const id = crypto.randomUUID();
    const payload = encryptItem(personal, id, { name: "GitHub", password: "p@ss" });

    const moved = { key: rewrapItemKey(personal, collection, id, payload.key), data: payload.data };
    expect(decryptItem<{ name: string }>(collection, id, moved).data.name).toBe("GitHub");
    expect(() => decryptItem(personal, id, moved)).toThrow(CryptoError);
  });

  it("cannot be decrypted under another item id", () => {
    const key = generateSymmetricKey();
    const payload = encryptItem(key, "id-1", { x: 1 });
    expect(() => decryptItem(key, "id-2", payload)).toThrow(CryptoError);
  });
});

describe("public-key sharing", () => {
  it("seals a collection key to a member", () => {
    const member = generateKeyPair();
    const other = generateKeyPair();
    const collectionKey = generateSymmetricKey();
    const sealed = sealKey(collectionKey, member.publicKey);
    expect(Buffer.from(openSealedKey(sealed, member.publicKey, member.privateKey))).toEqual(Buffer.from(collectionKey));
    expect(() => openSealedKey(sealed, other.publicKey, other.privateKey)).toThrow(CryptoError);
  });

  it("fingerprint is deterministic and bound to the account", () => {
    const kp = generateKeyPair();
    const a = publicKeyFingerprint(kp.publicKey, "alice@example.com");
    expect(a).toMatch(/^\d{5}( \d{5}){5}$/);
    expect(publicKeyFingerprint(kp.publicKey, "ALICE@example.com")).toBe(a);
    expect(publicKeyFingerprint(kp.publicKey, "bob@example.com")).not.toBe(a);
    expect(publicKeyFingerprint(generateKeyPair().publicKey, "alice@example.com")).not.toBe(a);
  });
});

describe("password generator", () => {
  it("has the requested length and every character class", () => {
    for (let i = 0; i < 200; i++) {
      const p = generatePassword({ length: 12 });
      expect(p).toHaveLength(12);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).toMatch(/[^a-zA-Z0-9]/);
    }
  });

  it("can exclude look-alike characters", () => {
    const p = generatePassword({ length: 128, avoidAmbiguous: true });
    expect(p).not.toMatch(/[0O1lI|]/);
  });

  it("strength estimate orders sensibly", () => {
    expect(estimateStrength("").score).toBe(0);
    expect(estimateStrength("aaaaaaaa").score).toBe(0);
    expect(estimateStrength("123456").score).toBe(0);
    expect(estimateStrength(generatePassword({ length: 20 })).score).toBe(4);
  });
});

function hasSshKeygen(): boolean {
  try {
    execFileSync("ssh-keygen", ["-?"], { stdio: "ignore" });
    return true;
  } catch (e) {
    return (e as { status?: number }).status !== undefined;
  }
}

describe("SSH keys", () => {
  it("generates Ed25519 keys consistent with the parser", () => {
    const key = generateEd25519SshKey("user@laptop");
    expect(key.publicKey).toMatch(/^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA[A-Za-z0-9+/]+ user@laptop$/);
    const parsed = parseOpenSshPrivateKey(key.privateKey)!;
    expect(parsed.publicKey).toBe(key.publicKey);
    expect(parsed.fingerprint).toBe(key.fingerprint);
    expect(parsed.encrypted).toBe(false);
    expect(fingerprintFromPublicKey(key.publicKey)).toBe(key.fingerprint);
  });

  it.runIf(hasSshKeygen())("generated key is accepted by ssh-keygen", () => {
    const key = generateEd25519SshKey("test@vault");
    const dir = mkdtempSync(join(tmpdir(), "vault-ssh-"));
    try {
      const file = join(dir, "id_ed25519");
      writeFileSync(file, key.privateKey);
      chmodSync(file, 0o600);
      const pub = execFileSync("ssh-keygen", ["-y", "-f", file], { encoding: "utf8" }).trim();
      expect(pub).toBe(key.publicKey);
      const fp = execFileSync("ssh-keygen", ["-l", "-f", file], { encoding: "utf8" });
      expect(fp).toContain(key.fingerprint);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(hasSshKeygen())("parses RSA and passphrase-protected keys from ssh-keygen", () => {
    const dir = mkdtempSync(join(tmpdir(), "vault-ssh-"));
    try {
      const rsa = join(dir, "rsa");
      execFileSync("ssh-keygen", ["-t", "rsa", "-b", "2048", "-N", "", "-C", "rsa@test", "-f", rsa], { stdio: "ignore" });
      const parsedRsa = parseOpenSshPrivateKey(execFileSync("cat", [rsa], { encoding: "utf8" }))!;
      const realFp = execFileSync("ssh-keygen", ["-l", "-f", rsa], { encoding: "utf8" });
      expect(parsedRsa.keyType).toBe("ssh-rsa");
      expect(realFp).toContain(parsedRsa.fingerprint);

      const enc = join(dir, "enc");
      execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "passphrase123", "-f", enc], { stdio: "ignore" });
      const parsedEnc = parseOpenSshPrivateKey(execFileSync("cat", [enc], { encoding: "utf8" }))!;
      expect(parsedEnc.encrypted).toBe(true);
      expect(execFileSync("ssh-keygen", ["-l", "-f", enc + ".pub"], { encoding: "utf8" })).toContain(parsedEnc.fingerprint);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns null for non-OpenSSH keys", () => {
    expect(parseOpenSshPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")).toBeNull();
  });
});

describe("passphrases", () => {
  it("uses EFF words with separator, capitals and one digit", () => {
    const p = generatePassphrase({ words: 6, separator: "-", capitalize: true, includeNumber: true });
    const parts = p.split("-");
    expect(parts).toHaveLength(6);
    expect(parts.filter((w) => /\d$/.test(w))).toHaveLength(1);
    for (const w of parts) {
      expect(w[0]).toBe(w[0]!.toUpperCase());
      expect(EFF_LARGE_WORDLIST).toContain(w.replace(/\d$/, "").toLowerCase());
    }
  });
  it("honors options and bounds", () => {
    const p = generatePassphrase({ words: 3, separator: " ", capitalize: false, includeNumber: false });
    expect(p.split(" ")).toHaveLength(3);
    expect(p).toBe(p.toLowerCase());
    expect(p).not.toMatch(/\d/);
    expect(generatePassphrase({ words: 1 }).split("-")).toHaveLength(3);
    expect(generatePassphrase({ words: 99 }).split("-")).toHaveLength(20);
  });
  it("wordlist has 7776 unique words; 5 words is about 64 bits", () => {
    expect(new Set(EFF_LARGE_WORDLIST).size).toBe(7776);
    expect(passphraseEntropyBits({ words: 5, includeNumber: false })).toBeCloseTo(64.6, 1);
    const seen = new Set(Array.from({ length: 50 }, () => generatePassphrase()));
    expect(seen.size).toBe(50);
  });
});
