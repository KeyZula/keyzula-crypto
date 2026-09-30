# @keyzula/crypto

Client-side encryption library used by [KeyZula](https://keyzula.com), a zero-knowledge password manager.
The web vault, browser extensions, mobile apps and CLI all use this code to derive keys and to
encrypt and decrypt vault data. The server only ever receives ciphertext, public keys and verifiers.

Built on [libsodium](https://libsodium.org) (`libsodium-wrappers-sumo`) and
[`@noble/hashes`](https://github.com/paulmillr/noble-hashes).

## Primitives

| Purpose | Algorithm |
| --- | --- |
| Password-based key derivation | Argon2id (libsodium `crypto_pwhash`, v1.3), 16-byte random salt |
| Subkey derivation | HKDF-SHA256 with distinct `info` labels |
| Symmetric encryption | XChaCha20-Poly1305 (IETF), random 192-bit nonce, AAD context binding |
| Public-key encryption | X25519 sealed boxes (`crypto_box_seal`) |
| Fingerprints | BLAKE2b-256 |
| Randomness | libsodium `randombytes_buf` / `randombytes_uniform` |

## Key hierarchy

```
master password ──Argon2id──▶ master key ──HKDF──┬─▶ auth hash   (sent to server, stored as Argon2id hash)
                                                  └─▶ KEK         (never leaves the client)
KEK ──wraps──▶ user key (256-bit, random)
user key ──encrypts──▶ X25519 private key, folder names, personal item keys
item key (per item) ──encrypts──▶ item data, attachment keys
collection key ──wraps──▶ item keys of shared items; sealed to each member's public key
```

- **KDF defaults:** 3 iterations, 64 MiB. Clients reject parameters outside 2–10 iterations and
  19 MiB–1 GiB (`assertSafeKdf`), so a server cannot downgrade or exhaust the KDF.
  Passwords are NFKC-normalized.
- **Password change** re-wraps the user key under a new KEK with a new salt. Items are not re-encrypted.
- **Each item** has its own random key. Moving an item between the personal vault and a collection
  re-wraps only the item key (`rewrapItemKey`).

## Ciphertext format and AAD

Symmetric ciphertexts are serialized as `v1.<nonce>.<ciphertext>` (base64url, no padding).
Every encryption binds a context string as associated data, so a ciphertext cannot be moved to
another record or field without failing authentication:

| Value | AAD |
| --- | --- |
| User key (wrapped by KEK) | `vault/v1/user-key` |
| Account private key | `vault/v1/private-key` |
| Item key | `vault/v1/item-key:<itemId>` |
| Item data | `vault/v1/item:<itemId>` |
| Folder / collection name | `vault/v1/folder:<id>`, `vault/v1/collection:<id>` |
| Attachment key / metadata | `vault/v1/attachment-key:<id>`, `vault/v1/attachment-meta:<id>` |
| Send key / content | `vault/v1/send-key:<id>`, `vault/v1/send:<id>` |
| PIN / reload / passkey / trusted-device wrapped user key | `vault/v1/pin-user-key`, `vault/v1/reload-user-key`, `vault/v1/passkey-user-key`, `vault/v1/device-user-key` |

## Attachments (KZA1)

```
file  = "KZA1" || chunk_0 || ... || chunk_n
chunk = nonce (24 bytes) || XChaCha20-Poly1305(plaintext, up to 1 MiB) incl. 16-byte tag
AAD   = "vault/v1/attachment:<id>" || 0x00 || u32be(index) || u8(isFinal)
```

Each attachment has its own random key, wrapped with the item key. Binding the index and a final-chunk
flag prevents reordering, truncation and mixing chunks between files.

## Sharing

- Every account has an X25519 key pair. Collection keys are sealed to each member's public key
  (`sealKey` / `openSealedKey`).
- `publicKeyFingerprint(publicKey, accountId)` yields six groups of five digits that admins and members
  can compare out of band to detect a substituted public key.
- **Send:** content is encrypted with a random link key that travels only in the URL fragment.
  An optional password is checked with a BLAKE2b verifier keyed by the link key.
- **Service accounts:** a 256-bit token secret is split with HKDF into an auth key (server stores
  SHA-256 of it) and a wrap key that decrypts the token's X25519 private key locally.

## Unlock methods

- **Passkey (WebAuthn PRF):** `deriveKeyFromPrf` turns the PRF output into a key that wraps the user key.
  The PRF output never leaves the device.
- **PIN and reload unlock:** `deriveUnlockKey(serverShare, localSecret)` = HKDF over a local secret and a
  random 32-byte share held by the server. The server releases the share only to the owning session
  (and, for PINs, only after a correct PIN verifier, with a limited number of attempts), so a locally
  stored wrapped key cannot be attacked offline on its own.
- **SSO without a master password:** the user key is wrapped with a device key that stays on a trusted
  device, sealed to a new device's ephemeral key during approval, or sealed to the organization's public
  key for disclosed admin recovery (`src/sso.ts`).

## Verifying the zero-knowledge claim

1. Read `src/account.ts` and `src/kdf.ts`: the only values derived from your password that leave the
   client are the auth hash (HKDF output, domain-separated from the KEK) and ciphertexts.
2. Run the tests (`npm test`); they cover wrong keys, AAD mismatches, tampering, KDF bounds and the
   attachment format.
3. Open the KeyZula web vault at `app.keyzula.com`, use your browser's developer tools (Network tab),
   and inspect requests while logging in and saving an item: request bodies contain `authHash`,
   `v1.`-prefixed ciphertexts and public keys only.
4. Decrypt a captured `v1.` value with this library and your own keys to confirm the format matches.

The server, web vault, extensions and mobile apps are not open source. The overall design, including what
the server can and cannot see, is described in the
[KeyZula Security Whitepaper](https://keyzula.com/docs/keyzula-security-whitepaper-en.pdf).

## Usage

```ts
import { initCrypto, createAccount, deriveFromPassword, unlockKeys, encryptItem, decryptItem } from "@keyzula/crypto";

await initCrypto();
const { material } = createAccount("correct horse battery staple");
const { kek } = deriveFromPassword("correct horse battery staple", material.kdf);
const keys = unlockKeys(kek, material);

const payload = encryptItem(keys.userKey, itemId, { name: "Example", password: "s3cret" });
const { data } = decryptItem(keys.userKey, itemId, payload);
```

The package ships TypeScript sources (`src/index.ts`) and is consumed through a bundler. It is not
published to npm.

## Development

```sh
npm ci
npm run typecheck
npm test
```

Requires Node.js 22 or later. This repository is a mirror of the library used in KeyZula's
products; changes are made upstream and exported here.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities to info@keyzula.com (subject: `Güvenlik`).

## License

Apache License 2.0. Copyright 2026 Netlen İnternet Hizmetleri Ltd. Şti. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). The EFF wordlist in `src/wordlist.ts` is licensed under CC BY 3.0 US.

---

## Türkçe

KeyZula'nın istemci tarafı şifreleme kütüphanesidir. Web kasası, tarayıcı eklentileri, mobil
uygulamalar ve komut satırı aracı anahtar türetme ve şifreleme için bu kodu kullanır; sunucu yalnızca
şifreli veri, açık anahtar ve doğrulayıcı görür. Ana parola Argon2id ile işlenir, kayıtlar
XChaCha20-Poly1305 ile kayıt kimliğine bağlı olarak şifrelenir, paylaşım X25519 mühürlü kutularla
yapılır. Sunucu ve uygulamaların kaynak kodu kapalıdır; genel tasarım
[KeyZula Güvenlik Tasarımı](https://keyzula.com/docs/keyzula-security-whitepaper-tr.pdf) belgesinde
anlatılır. Güvenlik bildirimleri: info@keyzula.com, konu "Güvenlik".
