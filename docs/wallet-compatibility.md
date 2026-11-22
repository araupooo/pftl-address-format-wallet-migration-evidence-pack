# Wallet compatibility

[FACT] Four implementations were tested in the lab. Three are libraries
that generate and derive keys; the fourth is the node itself, tested
through its public RPC. No real wallet app was tested (gap G-01/G-02).

## Tested implementations

| # | Implementation | Version | Role | Result |
| --- | --- | --- | --- | --- |
| 1 | Reference implementation (this pack) | `src/address_codec.py`, pure Python stdlib | Codec, derivation, signing, verification | PASS (25/25 drill cases) |
| 2 | xrpl-py | 5.2.0 (pip) | Derivation, X-address codec, offline transaction signing | PASS (24/24 cross-checks) |
| 3 | ripple-keypairs + ripple-address-codec | npm (latest at 2026-11-22) | Derivation, X-address codec, offline signing | PASS (24/24 cross-checks) |
| 4 | postfiatd public RPC (testnet) | 1.0.9, network_id 2025 | `account_info` parsing behaviour | PASS (9 account_info probes) |

Counts (recomputed from this table): 4 implementations tested.

## What agrees

[FACT] All three libraries agree byte-for-byte on:

- Key derivation from a seed, both curves, ordinals 0 and 1 (4 seeds x 2
  curves = 8 derivations).
- Classic-address encoding of every derived key.
- X-address encoding (mainnet tag 0, testnet tag 12345, mainnet no-tag) for
  every derived address.
- Offline transaction signatures: the signed Payment for each seed/curve is
  byte-identical across all three implementations (8 signatures), and the
  reference implementation verifies both foreign signatures.

[FACT] The node agrees with the libraries on parsing: it accepts the
classic addresses and the account-public token form, and it rejects
X-addresses and malformed input with `actMalformed` (measured live).

## What differs

[FACT] The differences are in scope, not in the formats:

- **X-addresses exist only in the libraries.** The node has no X-address
  code (0 matches in `src/` + `include/`). A wallet that shows an
  X-address must convert it to classic + tag before any RPC call.
- **The node cannot propose wallets.** `wallet_propose` returns HTTP 403
  Forbidden on the public proxy. Wallet generation is a client-library job.
- **Ed25519 has no ordinal family; secp256k1 does.** All three libraries
  agree on this because they all implement the pinned derivation, but a
  wallet UI that offers "next account" for an Ed25519 seed is inventing
  behaviour the protocol does not define.
- **Mnemonics are wallet-side only.** None of the three libraries in this
  pack was tested with a mnemonic, and the node has no mnemonic code. A
  mnemonic wallet's derivation path is its own choice.

## Import / export matrix

| From \ To | Family seed | RFC1751 words | Hex seed | Passphrase | Classic address | X-address |
| --- | --- | --- | --- | --- | --- | --- |
| Family seed | — | yes (lossless) | yes (lossless) | no (different secret) | yes (derive) | yes (derive + encode) |
| RFC1751 words | yes (lossless) | — | yes (lossless) | no | yes (derive) | yes (derive + encode) |
| Hex seed | yes (lossless) | yes (lossless) | — | no | yes (derive) | yes (derive + encode) |
| Passphrase | no | no | no | — | yes (derive) | yes (derive + encode) |
| Classic address | no (one-way) | no | no | no | — | yes (needs tag) |
| X-address | no (one-way) | no | no | no | yes (drops tag) | — |

[ANALYSIS] The matrix is one-way by design: addresses are hashes of public
keys, and nothing recovers a seed from an address. The lossy step is
X-address -> classic address, which drops the destination tag; the reverse
needs the tag supplied separately.

## Real wallet apps

[FACT] No real wallet app (Xumm, Crossmark, GemWallet, Ledger, or any
other) was installed or driven in this lab, so no claim is made about
their import behaviour (claim C-29 UNVERIFIED, gaps G-01/G-02). The
libraries tested here are the ones those apps are built on, which is
encouraging but not a substitute for testing the apps themselves.
