# Security policy

KeyZula is a zero-knowledge password manager. This repository contains the
client-side encryption library used by the KeyZula apps. We take reports about
it, and about any other part of KeyZula, seriously.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security problems.

Email **info@keyzula.com** with the subject **`Güvenlik`** (Turkish for "Security") and include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version or commit, and
- how you would like to be credited (or that you prefer to stay anonymous).

We will acknowledge your report, keep you informed while we investigate, and
coordinate disclosure with you once a fix is available. Please give us a
reasonable amount of time to fix the issue before disclosing it publicly, and
do not access or modify other users' data while testing.

## Scope

- This library (`src/`): key derivation, symmetric and public-key encryption,
  the attachment format, sharing, unlock and token helpers.
- The KeyZula service (`keyzula.com`, `app.keyzula.com`), browser extensions
  and mobile apps. Their source code is not public, but reports are welcome at
  the same address.

## Türkçe

Güvenlik açıklarını lütfen herkese açık issue olarak değil, **info@keyzula.com**
adresine **"Güvenlik"** konulu e-postayla bildirin. Açıklamayı, yeniden üretme
adımlarını ve etkilenen sürümü ekleyin; düzeltme yayımlanana kadar açığı
kamuya duyurmamanızı rica ederiz.
