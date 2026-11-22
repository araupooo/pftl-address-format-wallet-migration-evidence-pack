# Lab migration drill report

[FACT] The drill ran 2026-11-22 22:24:25 UTC in the pack directory, using
freshly generated LAB seeds (3 seeds, `os.urandom`), the reference
implementation, and the live testnet probe outputs. Result: **25/25 cases
PASS**. The unedited log is `outputs/drill-run.log`; the structured results
are `outputs/derived/drill-results.json`. Lab seeds were never written to
disk; only derived public material is recorded.

## Known-vector cases (public docs seed)

| Case | What was checked | Result |
| --- | --- | --- |
| D-01 | Docs seed, secp256k1 ordinal 0 -> pub `0330e7fc...`, address `rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh` | PASS |
| D-02 | Docs seed, Ed25519 -> pub `edaac3f9...`, address `rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf` | PASS |
| D-03 | `generateSeed("masterpassphrase")` reproduces the docs seed | PASS |
| D-04 | X-address vectors: main tag 0 `XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF`, test tag 12345 `TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49Mhpsws` | PASS |
| D-05 | RFC1751: 12 words `I IRE BOND BOW TRIO LAID SEAT GOAL HEN IBIS IBIS DARE`, round-trip + parity rejection | PASS |
| D-14 | Ed25519 RFC 8032 section 7.1 vectors 1–3 | PASS (3/3) |
| D-15 | Account-public / account-secret Base58Check tokens round-trip | PASS |

## Fresh LAB seed cases (3 seeds x 2 curves)

| Case | What was checked | Result |
| --- | --- | --- |
| D-06 (x6) | Each LAB seed derives a valid classic address under both curves | PASS (6/6) |
| D-07 (x3) | secp256k1 ordinal 0 vs 1 give different addresses for the same seed | PASS (3/3) |
| D-08 (x3) | Same seed, Ed25519 vs secp256k1 give different addresses | PASS (3/3) |
| D-09 (x2) | Offline sign/verify, both curves, with tamper rejection | PASS (2/2) |

[FACT] Example LAB results (seed fingerprints only; seeds never recorded):
seed 1 -> Ed25519 `rGmvXCFFBGV6eByMPB6eY2phpzaEgbNm6M`, secp256k1
`raiytF46EqpGpScaX6b2DELu7oQJvk3kHh`; seed 2 -> Ed25519
`rno4YHFtSHwd335n6ybBofKfBsfViaJW6i`, secp256k1
`rNUmEDXTVP2CHcj649epSHBbHqD4kMUiED`; seed 3 -> Ed25519
`rXNe98TWuy1EfGW1EiuSMBTPZiNBVeJKS`, secp256k1
`rsT1qaoy9nnG5w2ZcAvQ6CADHA93EJCpJn`.

## Failure-mode matrix (D-10, 12/12 rejected)

Bad checksum, wrong version byte, invalid Base58 character, too-short
input, empty string, X-address tag overflow (> 2^32-1), X-address bad
prefix, X-address 64-bit tag flag, family seed wrong length, account-public
token wrong length, RFC1751 wrong word count, RFC1751 unknown word — all
rejected with a `ValueError`.

## Live-ledger cases

| Case | What was checked | Result |
| --- | --- | --- |
| D-11 | 25 live validator master keys -> 25 distinct valid classic addresses (first `rB4FqubLxGBCKcrFp6ZsTWiKqGKC6HqSuP`) | PASS |
| D-12 | PFTL genesis `r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA` parses, AccountID `f0633263b2e588395fcf15d406297e864f91aa35`, balance 96,999,999,999.99988 PFT | PASS |
| D-13 | Live ledger census: validated ledger 8,281,677 held 0 transactions, 0 classic-address fields, 0 X-address fields | PASS (vacuous window) |

## Cross-check (separate script, `scripts/crosscheck.py`)

[FACT] 24/24 checks PASS: for the docs seed and 3 fresh LAB seeds, the
reference implementation, xrpl-py 5.2.0, and ripple-keypairs +
ripple-address-codec agree byte-for-byte on derivation, classic/X-address
encoding, and offline transaction signatures (8 signatures, both curves).
The reference implementation verifies both foreign signatures. The
cross-check also measured the digest rule: verifying with the bare signing
hash fails for both curves; verifying with the serialized signing bytes
succeeds for both (finding F-04).

## Timings

Drill wall time 8.84 s (including the Ed25519 self-test at ~3.8 s).
Cross-check wall time 10.36 s. Both are lab-only timings on this VM, not
network measurements.
