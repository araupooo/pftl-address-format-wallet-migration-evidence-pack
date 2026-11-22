# Methodology

## Sources (in order of authority)

1. **Pinned postfiatd source** — commit
   `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10, PR #50 merge,
   v1.0.9). Verified from a local git checkout (`git rev-parse HEAD` plus
   `git log`); the unauthenticated GitHub API was rate-limited for the
   shared egress IP during verification (gap G-06). Every cited line number
   was checked with `grep -n` on that checkout. Verbatim excerpts live in
   `fixtures/source-excerpts/` with file, lines, and permalink.
2. **Live PFTL testnet** — public RPC `https://rpc.testnet.postfiat.org/`,
   network ID 2025, read-only. Probe window 2026-11-22 22:23:51–22:24:16 UTC,
   validated ledger seq 8,281,677. Unedited responses in `outputs/`.
3. **Client libraries** — xrpl-py 5.2.0 (Python) and ripple-keypairs +
   ripple-address-codec (JavaScript, npm), used as independent
   implementations for the cross-check, not as authorities.
4. **Standards** — RFC 8032 (Ed25519 test vectors), RFC 1751 (seed words),
   RFC 6979 (deterministic ECDSA nonces), BIP44 (coin type 144, cited only
   for the mnemonic discussion).

## Safety boundary (non-negotiable)

- LAB-ONLY: every seed and key in the drill and cross-check is freshly
  generated test material, clearly labelled LAB, never funded, never used
  on any network. Lab seeds are never written to disk (the cross-check
  passes them to its Node helper through a 0600 temp file that is deleted
  immediately after the run). Only derived public material is recorded.
- Read-only live observation: under 20 RPC calls, each a single read-only
  request. No transactions submitted, no flood traffic, no load.
- Offline signing only: the test transactions in the cross-check are built
  and signed locally and never broadcast.
- No live key material, no real user wallets, no credentials, no sessions.

## How the reference implementation was validated

`src/address_codec.py` (pure Python stdlib) was validated four ways:

1. **Known vectors**: the public docs seed `snoPBrXtMeMyMHUVTgbuqAfg1SUTb`
   derives to the exact secp256k1 public key and address that xrpl-py and
   ripple-keypairs produce, and `generateSeed("masterpassphrase")`
   reproduces that seed exactly.
2. **Three-way agreement**: 24/24 cross-checks — derivation, classic and
   X-address encoding, and offline transaction signatures agree
   byte-for-byte across the reference implementation, xrpl-py 5.2.0, and
   ripple-keypairs, for the docs seed and 3 fresh LAB seeds, both curves.
3. **Standards vectors**: Ed25519 passes RFC 8032 section 7.1 vectors 1–3;
   RIPEMD-160 matches its known vector for `"test"`.
4. **Failure matrix**: 12/12 malformed inputs are rejected (bad checksum,
   wrong version byte, invalid Base58 character, tag overflow, 64-bit tag
   flag, wrong lengths, bad RFC1751 words).

Two genuine bugs were found and fixed during validation, both in the
reference implementation (not the pinned source): a parity-byte overflow in
the RFC1751 encoder (`char(p) << 6` keeps only the low 2 bits of the
parity) and a 32-byte/16-byte slice error in `generateSeed`. Both are
documented here because they are exactly the class of mistake a migration
implementer can make.

## How live values were measured

- `scripts/probe_all.sh` issues the RPC calls and retains the unedited
  responses under `outputs/`, with a per-file HTTP status and SHA-256 in
  `outputs/probe-run.log`.
- `scripts/drill.py` runs the 25-case lab drill and writes
  `outputs/derived/drill-results.json` plus `outputs/drill-run.log`.
- `scripts/crosscheck.py` runs the 24-check three-way comparison (needs
  xrpl-py and the npm packages) and writes
  `outputs/crosscheck-results.json` plus `outputs/crosscheck-run.log`.
- `src/address_model.py` computes the collision model and the address
  inventory from the pinned constants and the measured values.
- `scripts/analyze.py` derives findings, claims, risks, and gaps from
  those outputs; every count is recomputed from the list it summarizes.

## How the fresh-clone reproduction works

`bash scripts/clean_reproduce.sh` copies the pack to a throwaway directory,
drops all generated outputs, re-runs the probe, drill, model, and analysis
from scratch, and compares the fresh derived values with the shipped ones
via `scripts/compare_reproduce.py`. It exits 0 only if every comparison
check passes. The fresh probe set is copied back into
`outputs/fresh-clone-*` as evidence. The cross-check is re-run only when
xrpl-py and the npm packages are available; otherwise it is skipped and the
shipped cross-check results stand as the (already verified) evidence.

## Labels

Every substantive claim in this pack carries one label: [FACT] for a
verified fact with source and date, [ESTIMATE] for a modelled or reported
number, [ANALYSIS] for an interpretation — never mixed. Claim statuses in
`docs/claim-index.md` are VERIFIED / SPECIFIED / UNVERIFIED / UNTESTABLE.
