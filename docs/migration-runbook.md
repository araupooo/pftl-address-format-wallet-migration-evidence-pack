# Migration runbook

[ANALYSIS] This runbook is for migrating a wallet — a seed, and the
accounts derived from it — between implementations (libraries, node
operators, or wallet apps), on the PFTL testnet. It is written from the
measured behaviour in this pack. Nothing here touches a live key: use LAB
seeds to rehearse every step before migrating real material, and never
paste a real seed into a tool you have not audited.

## Before you start

1. Identify the source: seed format (family seed / RFC1751 words / hex /
   passphrase / mnemonic), key type (Ed25519 / secp256k1), and — for
   secp256k1 — which ordinals hold accounts. [FACT] Ed25519 seeds hold
   exactly one account; secp256k1 seeds can hold many (finding F-08).
2. Identify the destination: which curve it defaults to, and whether it
   accepts the seed format you have. [FACT] A wallet defaulting to the
   other curve silently lands on a different, empty account (finding F-01).
3. Rehearse with a LAB seed through the whole runbook first. The reference
   implementation (`src/address_codec.py`) can derive both curves and all
   ordinals for any LAB seed.

## Migration steps

1. **Export** the seed from the source in its native format. Record the
   key type and the secp256k1 ordinals in use alongside the seed — the seed
   alone does not say which curve or which ordinals matter.
2. **Convert the seed format if needed.** Family seed <-> RFC1751 words <->
   hex are lossless conversions of the same 16 bytes; use the reference
   implementation or a client library. A passphrase is NOT convertible to a
   family seed: it is a different secret that happens to derive a seed.
   A mnemonic is NOT convertible to a family seed at all (finding F-05).
3. **Derive both curves** from the seed in the destination (or with the
   reference implementation) and **compare addresses** with the source
   before moving anything. If the source address matches the Ed25519
   derivation, the account is Ed25519; if it matches secp256k1 ordinal 0
   (or 1, 2, ...), the account is secp256k1 at that ordinal. Do not proceed
   until the addresses match exactly.
4. **Enumerate secp256k1 ordinals.** For a secp256k1 seed, derive ordinals
   0, 1, 2, ... and check each address on the ledger (`account_info`)
   until you have found every funded account. Stop after a run of
   unfunded ordinals that matches your own records — do not assume ordinal
   0 is the only account.
5. **Convert addresses for the destination.** If the destination stores
   X-addresses, convert classic + tag at the client boundary; never store
   an X-address where an account identifier is expected, because the node
   rejects X-addresses with `actMalformed` (finding F-02). Keep the
   destination tag in its own field.
6. **Verify offline first.** Sign a test transaction offline with the
   migrated key and verify it with the reference implementation before
   funding or using the migrated account. The cross-check in this pack
   shows the exact digest rule: sign the serialized signing bytes
   (`STX\0` || tx, SigningPubKey included), never the bare signing hash
   (finding F-04).
7. **Confirm on the ledger.** After importing, check each migrated address
   with `account_info` on the correct network (2025 for the testnet).
   [FACT] A classic address carries no network byte, so confirm the
   network out-of-band (finding F-03).

## Rollback

1. **The source seed is the rollback.** Migration does not move, delete, or
   invalidate anything on the ledger: the same seed still derives the same
   accounts in the source implementation. If the destination misbehaves,
   stop using it and return to the source.
2. **Do not delete the source wallet** until the destination has been
   verified on the ledger (step 7) for every migrated account.
3. **If the destination derived the wrong curve**, no funds are at risk
   unless funds were sent to the wrong-curve address. The wrong-curve
   address is a valid address controlled by the same seed under the other
   curve — recover it by deriving the other curve (finding F-01) and
   moving the funds, then re-do the migration with the curve recorded.
4. **If funds were sent to an X-address-derived classic address without
   its tag**, the funds are on the ledger at the classic address; the tag
   cannot be retroactively attached. Contact the recipient with the
   transaction hash and the intended tag.
5. **If a signature is rejected**, check the digest first (finding F-04):
   sign the serialized bytes, not the hash. Then check the key type and
   the network.

## What this runbook does not cover

- Mnemonic-to-family-seed migration: there is none, because the derivations
  differ (finding F-05). Treat a mnemonic wallet as a separate wallet and
  move funds with a transaction instead.
- Hardware wallets: untested in this lab (gap G-02). Do not assume a
  hardware wallet's derivation matches a family seed.
- Mainnet: there is no mainnet yet, and no conversion mechanism is
  established (gap G-04). This runbook is testnet-only until then.
