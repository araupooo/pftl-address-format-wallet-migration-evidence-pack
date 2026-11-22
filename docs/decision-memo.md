# Decision memo

## Verdict

**SOUND BUT FRAGILE AT THE EDGES — the address formats are correct and
interoperable across three independent implementations, and the node
rejects malformed input; every material risk sits at a boundary: curve
choice, network identity, and client-side-only X-addresses.**

## What is sound

[FACT] Three independent implementations — the reference implementation in
this pack, xrpl-py 5.2.0, and ripple-keypairs + ripple-address-codec —
agree byte-for-byte on key derivation, classic/X-address encoding, and
offline transaction signatures (24/24 cross-checks, 25/25 drill cases).
The formats are interoperable as implemented, not just as specified.

[FACT] The node behaves correctly at its boundary: it accepts well-formed
classic addresses and account-public tokens, returns `actNotFound` for
well-formed but unfunded addresses, and rejects X-addresses and malformed
input with `actMalformed` (9 live `account_info` probes). The 32-bit
checksum, the 160-bit AccountID space, and the 2-bit RFC1751 parity all do
their jobs as specified.

[FACT] The live testnet is consistent with the formats: 25 validator master
keys map to 25 distinct valid classic addresses, and the genesis account
parses and round-trips.

## What is fragile

1. **Curve choice is silent.** The same seed gives two different accounts,
   and nothing in the seed says which curve the account uses. A wallet
   defaulting to the other curve shows an empty account (F-01).
2. **Network identity is absent.** Classic addresses carry no network byte;
   the same address is valid on testnet and mainnet. Only X-addresses
   distinguish networks, and the node does not accept them (F-02, F-03).
3. **X-addresses are client-side only.** The node has no X-address code at
   all. Any tooling that treats an X-address as an account identifier breaks
   at the RPC layer (F-02).
4. **Mnemonics are a parallel universe.** The node has no mnemonic support,
   and mnemonic wallets derive by their own path. There is no
   mnemonic-to-family-seed migration (F-05).
5. **The signing digest is a trap for implementers.** secp256k1 signs
   SHA-512-Half(message); Ed25519 signs the message. Signing the bare
   signing hash fails verification for both curves (F-04, measured).
6. **There is no operator documentation.** `/docs/` returns 404 and the
   whitepaper does not specify address formats (F-06).

## Recommendations (in order)

1. **Record the key type and the secp256k1 ordinals alongside every seed,
   in every wallet and migration tool.** This one change neutralizes the
   highest-impact confusion risk (R-01, R-06).
2. **Convert X-addresses to classic + tag at the client boundary, and keep
   the tag in its own field.** Never persist an X-address where an account
   identifier is expected (R-02, R-04).
3. **Carry the network out-of-band in every payment flow** and confirm it
   before signing (R-03).
4. **Publish the address-format inventory as project documentation**
   (`docs/address-formats.md` in this pack is written for that purpose)
   (R-12).
5. **Sign the serialized signing bytes, never the bare signing hash**, and
   keep the three-way cross-check as the regression test for any future
   format change (R-07, F-12).
6. **Test real wallet apps and a hardware wallet** before mainnet
   (gaps G-01, G-02). The libraries agree; the apps built on them have not
   been tested here.

## What would change this verdict

- A mainnet launch with a published conversion specification would resolve
  the network-identity question empirically (gap G-04).
- Testing real wallet apps would either confirm the library-level agreement
  or surface app-level import differences (gap G-01).
- A project-published address-format specification would close the
  documentation gap (gap G-07).

## Numbers behind the verdict

- Findings: 12 (3 HIGH / 5 MEDIUM / 3 LOW / 1 INFO; 8 MEASURED / 4 SPECIFIED)
- Claims: 32 (20 VERIFIED / 8 SPECIFIED / 2 UNVERIFIED / 2 UNTESTABLE)
- Risks: 14 (3 HIGH / 6 MEDIUM / 4 LOW / 1 INFO)
- Gaps: 7
- Drill: 25/25 PASS; cross-check: 24/24 PASS; failure matrix: 12/12 rejected
- Live: postfiatd 1.0.9, network 2025, validated ledger 8,281,677
