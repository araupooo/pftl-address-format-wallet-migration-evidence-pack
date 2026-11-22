# PFTL Address-Format and Wallet Migration Evidence Pack

A public assessment of PFTL address formats, seed formats, and wallet
migration — built from the pinned protocol source, the live testnet, and a
lab migration drill with freshly generated keys. Assessment and lab drills
only: no live key material was used, no transactions were sent, no flood
traffic was generated, no mainnet was touched, nothing was signed on the
live network.

## Verdict

**SOUND BUT FRAGILE AT THE EDGES — the address formats are correct and
interoperable across three independent implementations, and the node
rejects malformed input; every material risk sits at a boundary: curve
choice, network identity, and client-side-only X-addresses.** The same seed
gives two different accounts depending on the curve (Ed25519 vs secp256k1),
classic addresses carry no network identity (the same address is valid on
testnet and mainnet), and X-addresses — the only format that distinguishes
networks and carries a destination tag — do not exist in the node at all:
the node rejects them with `actMalformed`. See `docs/decision-memo.md` for
the full assessment.

## Headline measured numbers (live testnet, network 2025, 2026-11-22 22:23 UTC)

| Measurement | Value |
| --- | --- |
| Build / network / state | postfiatd 1.0.9, network_id 2025, `full`, 21 peers |
| Validated ledger | seq 8,281,677 at probe start |
| Validation quorum | 17 of 25 (67%) |
| Validators in the live list | 25, all Ed25519 master keys |
| Validator master keys -> classic addresses | 25 distinct, all valid |
| PFTL genesis account | r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA, balance 96,999,999,999.99988 PFT |
| XRPL genesis address on PFTL | parses, does not exist (`actNotFound`) |
| X-address in `account_info` | rejected (`actMalformed`) |
| Malformed address in `account_info` | rejected (`actMalformed`) |
| `wallet_propose` via public proxy | HTTP 403 Forbidden |
| Explorer health endpoint | HTTP 500 `{"message":"rippled unreachable"}` |
| Project docs (`/docs/`) | HTTP 404 — no address/wallet documentation |

## Headline drill results (lab, freshly generated keys)

| Check | Result |
| --- | --- |
| Drill cases | 25/25 PASS |
| Cross-implementation checks (reference vs xrpl-py 5.2.0 vs ripple-keypairs) | 24/24 PASS |
| Failure-mode matrix (malformed inputs rejected) | 12/12 rejected |
| Ed25519 RFC 8032 test vectors 1–3 | 3/3 PASS |
| Offline signatures byte-identical across all three implementations | 8/8 (both curves, 4 seeds) |

## Headline modelled numbers (pinned constants)

| Model | Value |
| --- | --- |
| AccountID collision probability at 1e9 accounts (2^160 space) | ~3.4e-31 |
| AccountID collision probability at 2^80 accounts | ~0.39 |
| Expected undetected single-character corruptions of a 34-char classic address | ~4.5e-7 of 1,938 |
| Destination-tag space | 2^32 (0..4,294,967,295) |
| X-address variants per account | 2 networks x (1 no-tag + 2^32 tagged) |

## Contents

- `docs/address-formats.md` — the 9 inventoried address formats with encoding rules and worked examples
- `docs/seed-formats.md` — the 4 seed formats and the key-derivation paths
- `docs/wallet-compatibility.md` — import/export compatibility across the 4 tested implementations
- `docs/migration-runbook.md` — migration runbook with rollback steps
- `docs/drill-report.md` — the 25-case lab migration drill
- `docs/risk-analysis.md` — address-collision and confusion analysis
- `docs/decision-memo.md` — verdict, reasoning, and recommendations
- `docs/methodology.md` — how everything was measured
- `docs/claim-index.md` — 32 claims with status and primary source
- `docs/risk-register.md` — 14 risks
- `docs/gap-register.md` — 7 gaps
- `docs/evidence-index.md` — where every piece of evidence lives
- `docs/citations.md` — primary sources with pinned line numbers
- `src/address_codec.py` — reference implementation (pure Python stdlib)
- `src/address_model.py` — collision/confusion model
- `scripts/` — probe, drill, cross-check, analysis, reproduction, digest tools
- `fixtures/source-excerpts/` — 24 verbatim pinned-source excerpts with permalinks
- `fixtures/rfc1751-words.csv` — the 2048-word RFC1751 dictionary from the pinned source
- `fixtures/address-test-vectors.csv` — known-answer test vectors

## Reproduce

```bash
bash scripts/clean_reproduce.sh   # re-probes, re-drills, re-models, compares; exit 0 on match
bash scripts/verify_digests.sh    # verifies SHA256SUMS; exit 0
```

The cross-check (`scripts/crosscheck.py`) needs xrpl-py and the npm
packages installed; `clean_reproduce.sh` re-runs it only when they are
available and treats it as extended evidence otherwise.

## Counts (recomputed from their tables)

- Findings: 12 (3 HIGH / 5 MEDIUM / 3 LOW / 1 INFO; 8 MEASURED / 4 SPECIFIED)
- Claims: 32 (20 VERIFIED / 8 SPECIFIED / 2 UNVERIFIED / 2 UNTESTABLE)
- Risks: 14 (3 HIGH / 6 MEDIUM / 4 LOW / 1 INFO)
- Gaps: 7
- Address formats inventoried: 9; key formats: 2; seed formats: 4
- Wallets/implementations tested: 4 (reference, xrpl-py 5.2.0,
  ripple-keypairs + ripple-address-codec, postfiatd public RPC).
  Real wallet apps were NOT tested (gap G-01/G-02).

## Lab-only boundary

All seeds and keys in the drill and cross-check are freshly generated LAB
test material, clearly labelled, never funded, never used on any network.
Lab seeds are never written to disk; only derived public material (public
keys, addresses, fingerprints, signatures, timings) is recorded. All
signing is offline. No transactions were submitted to any network.
