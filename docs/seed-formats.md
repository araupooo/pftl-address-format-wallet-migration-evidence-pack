# Seed formats and key derivation

[FACT] A PFTL seed is 128 bits of entropy with four serializations. All
four describe the same 16 bytes; which one a wallet shows is a presentation
choice, not a different secret.

## 1. Family seed (Base58Check `s...`)

[FACT] Version byte `0x21`, 16 bytes, Base58Check (`Seed.cpp:88-95`).
Example (public docs vector): `snoPBrXtMeMyMHUVTgbuqAfg1SUTb`, seed bytes
`dedce9ce67b451d852fd4e846fcde31c`. This is the canonical seed form: the one
`parseBase58<Seed>` accepts, and the one every client library generates.

## 2. RFC1751 words (12 words)

[FACT] The same 16 bytes as 12 words from the 2048-word dictionary, 6
words per 64-bit half with a 2-bit parity per half (`Seed.cpp:135-145`,
`RFC1751.cpp:42, 301-330, 409-460`). The seed bytes are reversed before
encoding. Example: the docs seed is
`I IRE BOND BOW TRIO LAID SEAT GOAL HEN IBIS IBIS DARE`.

[FACT] The 12-word form is the only seed serialization with error
detection: a corrupted word is rejected, and a valid-word substitution is
caught by the parity check (drill D-05, both measured). The family-seed and
hex forms have only the 32-bit Base58Check checksum (family seed) or no
check at all (hex).

## 3. Passphrase-derived seed

[FACT] `generateSeed(passphrase)` is the first 16 bytes of SHA-512-Half of
the passphrase (`Seed.cpp:76-86`). There is no salt, no iteration count, no
key-stretching: the passphrase IS the seed, deterministically. Measured:
`generateSeed("masterpassphrase")` reproduces the docs seed exactly
(drill D-03).

[ANALYSIS] A passphrase seed is only as strong as the passphrase. Because
there is no stretching, a weak passphrase is brute-forceable offline at
SHA-512 speed. Passphrase seeds should be treated as a legacy convenience,
never as the recommended way to create a wallet.

## 4. Hex seed (32 hex characters)

[FACT] `parseGenericSeed` accepts a 32-hex-character string as a seed
(`Seed.cpp:108-116`). It is the raw 16 bytes with no checksum and no error
detection. It exists for tooling and tests, not for users.

## Key derivation from a seed

[FACT] There are exactly two key types (KeyType.h:28-31), and the
derivation differs by type:

**Ed25519** (`SecretKey.cpp:309-327, 330-372`): the secret is
SHA-512-Half(seed) — 32 bytes. The public key is `0xED` + the 32-byte
Ed25519 public key derived from that secret. One seed gives exactly one
Ed25519 keypair; there is no ordinal family.

**secp256k1** (`SecretKey.cpp:86-118, 145-223`): the root key is
SHA-512-Half(seed || seq_be32), with seq starting at 0 and incrementing
until the result is a valid secret (at most 128 attempts). The Generator
then computes a tweak per ordinal: SHA-512-Half(generator_pubkey ||
ordinal_be32 || subseq_be32). The ordinal's secret is root + tweak (mod
the curve order); the public key is the compressed point (`0x02`/`0x03` +
32-byte x). Ordinal 0 is the default keypair; ordinal 1, 2, ... are
further accounts from the same seed.

[FACT] Measured (drill D-01/D-02/D-07, cross-check 24/24): the docs seed
gives Ed25519 address `rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf` and secp256k1
ordinal-0 address `rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh`; secp256k1 ordinal 1
gives a third, different address. All three implementations agree
byte-for-byte.

## What is NOT supported

[FACT] The pinned node has no BIP39/mnemonic support (0 relevant matches
for `mnemonic`/`bip39` in `src/`, `include/`, `docs/`). Mnemonic import is
entirely wallet-side: a wallet that accepts a mnemonic derives keys by its
own path (commonly BIP44, coin type 144 for XRP), which is a different
derivation from the family-seed Generator. The two paths must never be
mixed: a mnemonic and a family seed holding the "same" recovery material
produce different accounts (finding F-05, risk R-05).

## Seed-format summary

| # | Format | Entropy | Checksum / error detection |
| --- | --- | --- | --- |
| 1 | Family seed (`s...`) | 128 bits | 32-bit Base58Check checksum |
| 2 | RFC1751 12 words | 128 bits | 2-bit parity per 64-bit half |
| 3 | Passphrase-derived | passphrase-dependent | none (deterministic hash) |
| 4 | Hex seed (32 chars) | 128 bits | none |

Counts (recomputed from this table): 4 seed formats inventoried.
