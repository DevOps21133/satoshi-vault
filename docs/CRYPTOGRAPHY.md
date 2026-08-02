# Cryptography

**Rule zero: no cryptography is invented or hand-implemented here.** Every
primitive comes from an audited library; this codebase only *composes* them,
and every composition is listed below with its rationale.

## Primitives and where they come from

| Primitive | Library | Used for |
|-----------|---------|----------|
| secp256k1 ECDSA (RFC6979 deterministic, low-S enforced) | `@noble/curves` | legacy/SegWit signatures |
| secp256k1 Schnorr (BIP340) | `@noble/curves` | Taproot signatures |
| SHA-256 / SHA-512 / RIPEMD-160 / HMAC / PBKDF2 | `@noble/hashes` | txids, sighashes, BIP32, BIP39 seed (PBKDF2-HMAC-SHA512, 2048 iters per BIP39), hash160 |
| Argon2id | `@noble/hashes` | vault password KDF |
| AES-256-GCM | WebCrypto (`crypto.subtle`) | vault encryption |
| CSPRNG | `crypto.getRandomValues` (OS) | entropy baseline, quiz indices, change-position coin flip |
| base58check, bech32, bech32m, base64url | `@scure/base` | address & QR encodings |

`@noble/*` and `@scure/*` are the audited, zero-dependency libraries by
Paul Miller (audits by Cure53 et al. — see each repo's `audit/` directory).

## Compositions (the things an auditor should check)

### Seed generation

```
pool = SHA-256 sponge
absorb: camera frames (RGB, alpha stripped), mic PCM, pointer deltas+jitter,
        device motion, 32 bytes OS CSPRNG (always)
health: repetition-count + adaptive-proportion per source (SP 800-90B-style),
        plus a structural screen the 800-90B tests provably miss: a sample with
        too few distinct byte values, or one that repeats exactly at any lag up
        to 256 (a stuck 8-bit counter, 00 ff 00 ff …, a sawtooth), is dead.
        Unhealthy sources are excluded from the entropy *estimate* — including
        RETROACTIVELY (a source that fails later loses all credit it earned) —
        but their bytes still mix in (can't hurt, per the sponge argument)
credit: 1 bit per 8 sample bytes, capped at 64 bits per sample, so a single
        large frame cannot satisfy the target on its own
extract: SHA-256(pool state ‖ counter) → 16 or 32 bytes → BIP39 words
```

The UI refuses to generate until the *healthy* entropy estimate reaches the
target. The extracted bytes and intermediate buffers are zeroized after the
mnemonic is derived.

### BIP39 → BIP32

Standard: mnemonic → PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase,
2048) → 64-byte seed → HMAC-SHA512("Bitcoin seed") → master key. Verified
against the official BIP39/BIP32 test vectors in `packages/core/test/`.

### Signing

- Legacy: original Bitcoin sighash; SegWit v0: BIP143; Taproot: BIP341
  key-path with the BIP340 output-key tweak (`taprootOutputKey`).
- ECDSA signatures are RFC6979-deterministic with low-S normalization
  (BIP62); Schnorr per BIP340 with auxiliary randomness from the CSPRNG.
- Sighash type: `SIGHASH_ALL` only (`SIGHASH_DEFAULT` for Taproot).

### Vault at rest

```
salt   = 16 bytes CSPRNG
key    = Argon2id(password, salt, t=3, m=2^16 KiB (64 MiB), p=1, 32 bytes)
nonce  = 12 bytes CSPRNG (fresh per encryption, never reused for a key —
         each save derives from a fresh salt)
blob   = header(version ‖ KDF params ‖ salt ‖ nonce) ‖
         AES-256-GCM(key, nonce, plaintext, AAD = header)
```

Authenticating the header as AAD means an attacker cannot downgrade the KDF
parameters without failing decryption. The plaintext (the mnemonic JSON) is
zeroized after use; the BIP39 passphrase is **never stored** in any form.

### Zeroization

`zeroize()` overwrites byte arrays; `HDPrivateKey.wipe()` clears chain code
and key material; intermediate derivation nodes in change verification are
wiped in a `finally`. Caveat (documented honestly): JavaScript engines may
keep copies (GC, hidden classes, string interning of mnemonic words in the
DOM). Zeroization here is best-effort defense-in-depth, not a guarantee —
the primary defenses are the air gap and vault encryption.

### Constant-time comparisons

Secret-dependent comparisons use a constant-time `bytesEqual`; note GCM's
tag check inside WebCrypto is constant-time by construction.

## Known limitations

- The web platform cannot lock memory pages or prevent swap.
- `qrcode`/`jsqr` process public data only (never key material).
- Single-sig only; no PSBT script-path Taproot spends (key-path only).
