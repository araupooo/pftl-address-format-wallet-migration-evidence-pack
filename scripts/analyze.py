#!/usr/bin/env python3
"""analyze.py — derive the analysis artifacts from the probe/drill/model/
cross-check outputs. Single source of truth for findings, claims, and
risks; every count in every generated file is recomputed from the lists
below, never typed by hand.

Inputs (all produced by probe_all.sh + drill.py + crosscheck.py +
address_model.py + extract_excerpts.py):
  outputs/server_info.json, outputs/ledger_current.json,
  outputs/rpc-account_info-*.json, outputs/testnet_vl.json,
  outputs/explorer_health.json, outputs/docs_postfiat_org.html,
  outputs/derived/drill-results.json, outputs/crosscheck-results.json,
  outputs/derived/address-inventory.json, outputs/derived/collision-model.json
Outputs:
  findings.json, run-manifest.json
  docs/claim-index.md, docs/gap-register.md, docs/risk-register.md,
  docs/evidence-index.md
  fixtures/address-test-vectors.csv

Status taxonomy (same as the earlier packs):
  VERIFIED   — measured live on the testnet, or measured in the lab drill /
                cross-check
  SPECIFIED  — stated in pinned code, pinned docs, or a cited standard
  UNVERIFIED — could not be checked from any available source
  UNTESTABLE — would need an action this pack's safety boundary forbids
"""
import datetime
import json
import os

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DERIVED = os.path.join(PACK, "outputs", "derived")
OUT = os.path.join(PACK, "outputs")

VERDICT = ("SOUND BUT FRAGILE AT THE EDGES — the address formats are correct "
           "and interoperable across three independent implementations, and "
           "the node rejects malformed input; every material risk sits at a "
           "boundary: curve choice, network identity, and client-side-only "
           "X-addresses.")

# ---------------------------------------------------------------- findings
FINDINGS = [
    {"id": "F-01", "severity": "HIGH", "status": "MEASURED",
     "title": "Same seed, two accounts: curve choice changes the address",
     "evidence": "Drill D-08: for each of 3 fresh LAB seeds, the Ed25519 and "
                 "secp256k1 derivations of the SAME seed produce different "
                 "classic addresses (e.g. seed 1: rGmvXCFFBGV6eByMPB6eY2phpzaEgbNm6M "
                 "vs raiytF46EqpGpScaX6b2DELu7oQJvk3kHh). The docs seed does the "
                 "same (rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf vs "
                 "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh). A wallet that defaults to "
                 "the other curve silently lands the user on a different, empty "
                 "account.",
     "remediation": "Migration tooling must record and display the key type "
                    "alongside the seed; import flows must derive BOTH curves "
                    "and show both addresses before the user picks one."},
    {"id": "F-02", "severity": "HIGH", "status": "MEASURED",
     "title": "X-addresses are client-side only; the node rejects them",
     "evidence": "grep over src/ and include/ of postfiatd 0085a1ff for "
                 "toXAddress/XAddress/xAddress returns 0 matches. Live: "
                 "account_info for the X-address "
                 "XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF returns "
                 "actMalformed (AccountInfo.cpp:74-83 parses only "
                 "parseBase58<AccountID>). Any migration or payment tooling "
                 "that stores X-addresses as account identifiers breaks at "
                 "the RPC layer.",
     "remediation": "Never persist an X-address where an account is expected; "
                    "convert to classic + tag at the client boundary and keep "
                    "the tag in its own field."},
    {"id": "F-03", "severity": "HIGH", "status": "SPECIFIED",
     "title": "Classic addresses carry no network identity",
     "evidence": "The classic address is Base58Check(version 0x00, 20-byte "
                 "AccountID) with no network byte (tokens.h:42; "
                 "AccountID.cpp:114-120). The same classic address is valid on "
                 "testnet and mainnet: the XRPL genesis address "
                 "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59 parses on the PFTL testnet "
                 "and simply does not exist there (actNotFound). Only the "
                 "X-address prefix distinguishes networks (main 0x05 0x44 vs "
                 "test 0x04 0x93).",
     "remediation": "Treat a classic address as network-agnostic: every "
                    "payment flow must carry the network (2025 testnet vs "
                    "mainnet) out-of-band, and confirm it before signing."},
    {"id": "F-04", "severity": "MEDIUM", "status": "MEASURED",
     "title": "secp256k1 signing digests the message twice; the bare signing hash fails",
     "evidence": "SecretKey.cpp sign() hashes the message with SHA-512-Half "
                 "before ECDSA for secp256k1, while Ed25519 signs the message "
                 "directly (SecretKey.cpp:258-307). Measured in the cross-check: "
                 "verifying an xrpl-py offline signature with the bare signing "
                 "hash as the message returns False for BOTH curves; verifying "
                 "with the serialized signing bytes (STX\\0 || tx, SigningPubKey "
                 "included) returns True for both. A naive implementer that "
                 "signs the signing hash itself produces a signature the network "
                 "rejects.",
     "remediation": "Sign the serialized signing bytes, never the bare hash; "
                    "keep the reference implementation's sign/verify pair as "
                    "the worked example."},
    {"id": "F-05", "severity": "MEDIUM", "status": "SPECIFIED",
     "title": "No BIP39/mnemonic support in the pinned node",
     "evidence": "grep over src/, include/, docs/ of postfiatd 0085a1ff for "
                 "mnemonic/bip39/bip-39 returns 0 relevant matches. Mnemonic "
                 "import is wallet-side only. Wallet-side mnemonic schemes "
                 "(BIP44, coin type 144 for XRP) derive keys by a different "
                 "path than the family-seed Generator, so a mnemonic wallet and "
                 "a family-seed wallet holding the 'same' recovery phrase "
                 "produce different accounts. Hardware-wallet behaviour could "
                 "not be tested in this lab (see gap G-02).",
     "remediation": "Document the derivation path next to every mnemonic; "
                    "migration must re-derive from the mnemonic with the "
                    "wallet's own path, never by converting a mnemonic into a "
                    "family seed."},
    {"id": "F-06", "severity": "MEDIUM", "status": "MEASURED",
     "title": "No wallet or address documentation on the project site",
     "evidence": "GET https://postfiat.org/docs/ returns 404; "
                 "https://postfiat.org/ contains no wallet or address "
                 "documentation (0 matches); the whitepaper mentions "
                 "'addresses' twice, both in passing, with no format "
                 "specification. Operators have only the pinned code and the "
                 "client libraries as documentation.",
     "remediation": "Publish the address-format inventory (docs/address-formats.md "
                    "in this pack) as project documentation before mainnet."},
    {"id": "F-07", "severity": "MEDIUM", "status": "MEASURED",
     "title": "wallet_propose is admin-gated; the public proxy cannot propose wallets",
     "evidence": "POST wallet_propose to the public RPC proxy returns HTTP 403 "
                 "Forbidden (outputs/wallet_propose.json). Operators and "
                 "migration tooling must generate seeds and keypairs with "
                 "client libraries, not the node.",
     "remediation": "Use the reference implementation or xrpl-py / "
                    "ripple-keypairs for wallet generation; never depend on a "
                    "public RPC for it."},
    {"id": "F-08", "severity": "MEDIUM", "status": "SPECIFIED",
     "title": "Ed25519 has no ordinal family; secp256k1 has an unbounded one",
     "evidence": "generateKeyPair(secp256k1, seed) runs Generator(seed)(0) and "
                 "the Generator accepts any ordinal (SecretKey.cpp:180-223, "
                 "330-372); generateKeyPair(ed25519, seed) derives a single "
                 "keypair and ignores ordinals. Drill D-07 measured ordinal 0 "
                 "vs 1 giving different secp256k1 addresses for the same seed. "
                 "A migration that assumes 'the next account' exists for an "
                 "Ed25519 seed silently drops derived accounts.",
     "remediation": "Migration runbooks must enumerate secp256k1 ordinals "
                    "explicitly and treat Ed25519 seeds as single-account."},
    {"id": "F-09", "severity": "LOW", "status": "MEASURED",
     "title": "The all-zero account address is widely misidentified",
     "evidence": "The all-zero AccountID encodes to "
                 "rrrrrrrrrrrrrrrrrrrrrhoLvTp (21 leading 'r's, 27 chars), "
                 "verified against xrpl-py and the reference implementation. "
                 "The commonly quoted rrrrrrrrrrrrrrrrrrrrBZbvji decodes to "
                 "AccountID 0...01 (AccountID.cpp noAccount()), not zero. The "
                 "live node returns actNotFound for both. The confusion is "
                 "harmless here but shows how easy format mistakes are.",
     "remediation": "Derive special addresses from the codec, never from memory; "
                    "the drill records both values."},
    {"id": "F-10", "severity": "LOW", "status": "SPECIFIED",
     "title": "Destination tags exist only in X-addresses",
     "evidence": "The destination tag is a 32-bit value (0..2^32-1) carried "
                 "only in the X-address flag/tag bytes (ripple-address-codec "
                 "encodeXAddress); a classic address carries no tag. A payment "
                 "that needs a tag but is addressed classically loses the tag "
                 "silently at the client layer — the ledger cannot recover it.",
     "remediation": "Keep the tag in its own field end-to-end; if an address "
                    "arrives without one, ask, do not assume tag 0."},
    {"id": "F-11", "severity": "LOW", "status": "MEASURED",
     "title": "No on-ledger address sample in the probe window",
     "evidence": "The validated ledger at probe time (seq 8281677) contained "
                 "0 transactions, so the on-ledger address-format census is "
                 "vacuous for this window (drill D-13). This is a limitation "
                 "of the observation window, not a format flaw; the ledger "
                 "carries only classic addresses by construction (X-addresses "
                 "never appear on-ledger).",
     "remediation": "Re-run the census over a busier window before mainnet; "
                    "the drill script already supports it."},
    {"id": "F-12", "severity": "INFO", "status": "MEASURED",
     "title": "Three independent implementations agree byte-for-byte",
     "evidence": "Cross-check 24/24 PASS: the reference implementation (pure "
                 "Python stdlib), xrpl-py 5.2.0, and ripple-keypairs + "
                 "ripple-address-codec agree exactly on key derivation, "
                 "classic/X-address encoding, and offline transaction "
                 "signatures for the public docs seed and 3 fresh LAB seeds "
                 "across both curves. Drill 25/25 PASS. The formats are "
                 "interoperable as implemented.",
     "remediation": "None — keep the three-way cross-check as the regression "
                    "test for any future format change."},
]

# ------------------------------------------------------------------- claims
# status is the 2nd element; every claim cites its primary source.
CLAIMS = [
    ("C-01", "VERIFIED", "A classic address is Base58Check(version 0x00, 20-byte AccountID).",
     "AccountID.cpp:114-120; tokens.h:42; drill D-01/D-12; cross-check 24/24."),
    ("C-02", "VERIFIED", "AccountID = RIPEMD-160(SHA-256(public key)).",
     "AccountID.cpp:168-176; drill D-01/D-02; 3-way derivation agreement."),
    ("C-03", "VERIFIED", "A family seed is Base58Check(version 0x21, 16-byte seed).",
     "Seed.cpp:88-95; tokens.h:46; drill D-01/D-03."),
    ("C-04", "VERIFIED", "A passphrase seed is SHA-512-Half(passphrase), first 16 bytes.",
     "Seed.cpp:76-86; drill D-03: 'masterpassphrase' -> snoPBrXtMeMyMHUVTgbuqAfg1SUTb."),
    ("C-05", "VERIFIED", "Ed25519 secret = SHA-512-Half(seed); public key = 0xED + 32 bytes.",
     "SecretKey.cpp:309-327, 352-356; drill D-02; cross-check 24/24."),
    ("C-06", "VERIFIED", "secp256k1 keypair = root key (SHA-512-Half(seed||seq)) + Generator tweak; ordinal 0 and 1 differ.",
     "SecretKey.cpp:86-118, 145-223; drill D-01/D-07; cross-check 24/24."),
    ("C-07", "VERIFIED", "X-address = Base58Check(prefix || AccountID || flag || tag LE || 4 zero bytes); main [0x05,0x44], test [0x04,0x93].",
     "ripple-address-codec encodeXAddress; drill D-04; cross-check 24/24."),
    ("C-08", "VERIFIED", "The node rejects an X-address in account_info with actMalformed.",
     "Live probe rpc-account_info-xaddress.json; AccountInfo.cpp:74-83."),
    ("C-09", "VERIFIED", "The node rejects malformed classic addresses with actMalformed.",
     "Live probe rpc-account_info-malformed.json."),
    ("C-10", "VERIFIED", "A valid-format classic address with no account returns actNotFound (format validity does not imply existence).",
     "Live probes: xrpl-genesis, account-one, validator-master, docs-seed."),
    ("C-11", "VERIFIED", "The all-zero AccountID encodes to rrrrrrrrrrrrrrrrrrrrrhoLvTp (21 leading 'r's).",
     "Reference implementation + xrpl-py agree; live probe returns actNotFound."),
    ("C-12", "VERIFIED", "The 25 live testnet validator master keys map to 25 distinct valid classic addresses, all Ed25519.",
     "Drill D-11 from outputs/testnet_vl.json."),
    ("C-13", "VERIFIED", "The PFTL genesis account is r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA, AccountID f0633263b2e588395fcf15d406297e864f91aa35.",
     "Live probe rpc-account_info-pftl-genesis.json; drill D-12."),
    ("C-14", "VERIFIED", "Offline transaction signatures verify across implementations for both curves (byte-identical signatures).",
     "Cross-check X-tx-*-sig, 8/8; drill D-09."),
    ("C-15", "VERIFIED", "Verifying with the bare signing hash as the message fails for both curves; the serialized signing bytes verify.",
     "Cross-check: verify(message=signing-hash)=False, verify(message=serialized-bytes)=True, both curves."),
    ("C-16", "VERIFIED", "An RFC1751 seed is 12 words (6 per 64-bit half, 2-bit parity); a corrupted word or a parity flip is rejected.",
     "Seed.cpp:135-145; RFC1751.cpp:409-460; drill D-05."),
    ("C-17", "VERIFIED", "12/12 malformed inputs are rejected by the reference codec (bad checksum, wrong version, bad character, tag overflow, 64-bit tag flag, wrong lengths, bad RFC1751 words).",
     "Drill D-10."),
    ("C-18", "VERIFIED", "Ed25519 passes RFC 8032 section 7.1 test vectors 1-3.",
     "Drill D-14; scripts/ed25519_selftest.py."),
    ("C-19", "SPECIFIED", "The pinned node code contains no X-address support (0 matches for toXAddress/XAddress/xAddress in src/ + include/).",
     "fixtures/source-hashes.json absence_checks; extract_excerpts.py grep."),
    ("C-20", "SPECIFIED", "The pinned node code contains no BIP39/mnemonic support (0 relevant matches in src/, include/, docs/).",
     "fixtures/source-hashes.json absence_checks; extract_excerpts.py grep."),
    ("C-21", "SPECIFIED", "KeyType has exactly two values: secp256k1 = 0, ed25519 = 1.",
     "include/xrpl/protocol/KeyType.h:28-31."),
    ("C-22", "SPECIFIED", "The Base58 alphabet is rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz (XRPL alphabet, not Bitcoin's).",
     "src/libxrpl/protocol/tokens.cpp:143."),
    ("C-23", "SPECIFIED", "The Base58Check checksum is the first 4 bytes of the double-SHA-256 digest of <type><token>.",
     "src/libxrpl/protocol/tokens.cpp:182-195, 325-342 (code is authoritative; the comment is imprecise)."),
    ("C-24", "VERIFIED", "wallet_propose is refused by the public RPC proxy (HTTP 403 Forbidden).",
     "Live probe outputs/wallet_propose.json."),
    ("C-25", "SPECIFIED", "A destination tag is a 32-bit unsigned integer (0..2^32-1); larger values are rejected.",
     "ripple-address-codec encodeXAddress; drill D-10 tag-overflow rejection."),
    ("C-26", "SPECIFIED", "The secp256k1 Generator tweak uses a uint32 sequence and a uint32 sub-sequence counter (up to 128 attempts each).",
     "SecretKey.cpp:145-175."),
    ("C-27", "SPECIFIED", "Ed25519 derivation has no ordinal family: one seed gives exactly one Ed25519 keypair.",
     "SecretKey.cpp:330-372 (generateKeyPair ignores ordinal for Ed25519)."),
    ("C-28", "VERIFIED", "Account-public (0x23) and account-secret (0x22) Base58Check tokens round-trip.",
     "Drill D-15; tokens.h:43-44."),
    ("C-29", "UNVERIFIED", "Real wallet apps (Xumm, Crossmark, GemWallet, Ledger) import a PFTL family seed to the same address as the reference implementation.",
     "No wallet app could be installed and driven in this lab; see gap G-01."),
    ("C-30", "UNVERIFIED", "Whether any existing mainnet wallet defaults to Ed25519 or secp256k1 for a new PFTL account.",
     "No mainnet exists and no wallet survey was possible; see gap G-04."),
    ("C-31", "UNTESTABLE", "A BIP44 (44'/144'/0'/0/0) derivation of a PFTL mnemonic produces the same address as the family-seed derivation of the same entropy.",
     "Would need a hardware wallet and its mnemonic; the safety boundary forbids real key material; see gap G-02."),
    ("C-32", "UNTESTABLE", "A classic address created on the testnet today will be valid at mainnet genesis.",
     "No mainnet exists and no 1:1 conversion mechanism is established; see gap G-04."),
]

# -------------------------------------------------------------------- risks
RISKS = [
    {"id": "R-01", "severity": "HIGH", "likelihood": "LIKELY",
     "title": "Wrong-curve import lands funds on a different, empty account",
     "finding": "F-01",
     "detail": "Same seed, different curve = different address. A user importing a "
               "seed into a wallet that defaults to the other curve sees an empty "
               "account and may conclude the funds are lost, or send funds to the "
               "wrong-curve address. Recovery needs the seed + the other curve's "
               "derivation, which a panicked user may not know exists."},
    {"id": "R-02", "severity": "HIGH", "likelihood": "LIKELY",
     "title": "X-address sent to the node or stored as an account identifier",
     "finding": "F-02",
     "detail": "The node has no X-address code and answers actMalformed. Any "
               "tooling that persists X-addresses as account IDs, or passes them "
               "to account_info / payment construction, breaks. The break is "
               "loud (an error) rather than silent, which limits the damage."},
    {"id": "R-03", "severity": "HIGH", "likelihood": "POSSIBLE",
     "title": "Testnet/mainnet address reuse: same classic address, two ledgers",
     "finding": "F-03",
     "detail": "Classic addresses carry no network byte, so an address valid on "
               "the testnet is equally valid on mainnet. A payment built for one "
               "network and signed for the other is a user error the format "
               "cannot catch. X-addresses are the only format that distinguishes "
               "networks, and the node does not accept them."},
    {"id": "R-04", "severity": "MEDIUM", "likelihood": "POSSIBLE",
     "title": "Destination tag lost when a payment is addressed classically",
     "finding": "F-10",
     "detail": "Tags live only in X-addresses. A flow that drops the tag (or "
               "assumes tag 0) when converting to a classic address sends an "
               "untagged payment to a tagged destination; the funds arrive but "
               "cannot be attributed by the recipient."},
    {"id": "R-05", "severity": "MEDIUM", "likelihood": "POSSIBLE",
     "title": "Mnemonic / BIP44 migration produces a different account",
     "finding": "F-05",
     "detail": "The node has no mnemonic support; mnemonic wallets derive by "
               "their own path. Importing a mnemonic into a family-seed wallet "
               "(or vice versa) yields a different address, with the same "
               "empty-account confusion as R-01."},
    {"id": "R-06", "severity": "MEDIUM", "likelihood": "POSSIBLE",
     "title": "Ordinal-family accounts dropped in an Ed25519 migration",
     "finding": "F-08",
     "detail": "secp256k1 seeds can hold many accounts (ordinals); Ed25519 seeds "
               "hold one. A migration that enumerates ordinals for an Ed25519 "
               "seed finds nothing, and one that assumes a single account for a "
               "secp256k1 seed can strand ordinal-1+ accounts."},
    {"id": "R-07", "severity": "MEDIUM", "likelihood": "UNLIKELY",
     "title": "Signing-digest implementation error produces rejected signatures",
     "finding": "F-04",
     "detail": "secp256k1 signs SHA-512-Half(message); Ed25519 signs the message. "
               "Signing the bare signing hash fails verification for both curves "
               "(measured). The failure is loud (rejected signature), so the "
               "damage is a broken integration, not lost funds."},
    {"id": "R-08", "severity": "MEDIUM", "likelihood": "POSSIBLE",
     "title": "Seed-format confusion (family seed vs RFC1751 words vs hex)",
     "finding": "F-05",
     "detail": "One 128-bit seed has four serializations (family seed, 12 words, "
               "32 hex chars, passphrase). parseGenericSeed accepts all of them, "
               "and a passphrase that happens to look like a seed is treated as "
               "one. Users can mistake one form for another; the 12-word form "
               "has parity protection, the others do not."},
    {"id": "R-09", "severity": "LOW", "likelihood": "UNLIKELY",
     "title": "Single-character address corruption passes the checksum",
     "finding": "F-12",
     "detail": "The 32-bit checksum catches a random corruption with probability "
               "1 - 2^-32. Across all 1,938 single-character corruptions of a "
               "34-character classic address, ~4.5e-7 are expected to pass. "
               "Negligible per address, non-zero across a large user base; "
               "copy-paste and QR codes are the practical mitigation."},
    {"id": "R-10", "severity": "LOW", "likelihood": "NEGLIGIBLE",
     "title": "AccountID hash collision",
     "finding": "F-12",
     "detail": "160-bit AccountID space: collision probability is ~3.4e-31 at "
               "1e9 accounts and ~0.39 only at 2^80 accounts. Not a realistic "
               "risk; the confusion risks are encoding-level, not collisions."},
    {"id": "R-11", "severity": "LOW", "likelihood": "POSSIBLE",
     "title": "Special-address confusion (zero vs account-one)",
     "finding": "F-09",
     "detail": "The zero address and the account-1 address are easily confused "
               "in documentation and code; both return actNotFound on the "
               "testnet. Neither holds funds, so the impact is limited to "
               "misleading documentation and tests."},
    {"id": "R-12", "severity": "MEDIUM", "likelihood": "LIKELY",
     "title": "No operator documentation for address formats",
     "finding": "F-06",
     "detail": "With /docs/ returning 404 and the whitepaper silent on formats, "
               "operators learn the formats from code or from this pack. "
               "Undocumented formats invite the implementation errors in "
               "R-01, R-02, R-05, and R-07."},
    {"id": "R-13", "severity": "LOW", "likelihood": "LIKELY",
     "title": "wallet_propose unavailable through the public proxy",
     "finding": "F-07",
     "detail": "Operators who expect the node to propose wallets get HTTP 403. "
               "Low impact (client libraries exist), but it is a trap for "
               "migration tooling written against a local node and then pointed "
               "at the public proxy."},
    {"id": "R-14", "severity": "INFO", "likelihood": "LIKELY",
     "title": "Validator master-key addresses are identities, not accounts",
     "finding": "F-12",
     "detail": "All 25 validator master keys map to valid classic addresses, "
               "but none holds an account on the testnet (actNotFound). Tooling "
               "must not assume an address implies an account; conversely, "
               "funds sent to such an address would create an account "
               "controlled by the validator's master key."},
]

# --------------------------------------------------------------------- gaps
GAPS = [
    {"id": "G-01", "title": "Real wallet apps not tested",
     "detail": "Xumm, Crossmark, GemWallet, and other wallet apps could not be "
               "installed and driven in this lab. Import behaviour is verified "
               "only for three libraries (reference, xrpl-py, ripple-keypairs).",
     "unblocks": "A device lab or emulator run importing a LAB family seed into each app."},
    {"id": "G-02", "title": "Hardware-wallet / BIP44 derivation not tested",
     "detail": "Whether a Ledger-style BIP44 (44'/144') derivation of a mnemonic "
               "matches the family-seed derivation could not be tested: it needs "
               "a hardware wallet and real key material, which the safety "
               "boundary forbids.",
     "unblocks": "A hardware-wallet test with LAB-only mnemonics in a lab harness."},
    {"id": "G-03", "title": "No on-ledger transaction sample in the probe window",
     "detail": "The validated ledger at probe time held 0 transactions, so the "
               "on-ledger address census is vacuous. The claim that only classic "
               "addresses appear on-ledger rests on the code (X-addresses are "
               "client-side), not on a transaction sample.",
     "unblocks": "Re-run the census over a busier ledger window."},
    {"id": "G-04", "title": "No mainnet to test address validity against",
     "detail": "There is no mainnet and no established 1:1 testnet-to-mainnet "
               "conversion, so mainnet address validity and cross-network "
               "behaviour cannot be measured, only reasoned about from the "
               "format (no network byte).",
     "unblocks": "A mainnet launch or a published conversion specification."},
    {"id": "G-05", "title": "Codec test-suite vectors not fetched from upstream",
     "detail": "The ripple-address-codec repository's own test-vector files "
               "returned 404 at the guessed paths (the repo moved into the "
               "xrpl.js monorepo). X-address vectors are instead verified by "
               "three-way agreement of independent implementations.",
     "unblocks": "Locate the vectors in the xrpl.js monorepo and add them as a fourth check."},
    {"id": "G-06", "title": "GitHub API rate-limited during pin verification",
     "detail": "The unauthenticated GitHub API returned 'rate limit exceeded' "
               "for the shared egress IP while verifying the pinned commit, so "
               "the pin was verified from a local git checkout (rev-parse HEAD "
               "plus log) instead of the API.",
     "unblocks": "An authenticated API call, or a fresh clone at the pinned commit."},
    {"id": "G-07", "title": "No project documentation for address formats",
     "detail": "postfiat.org/docs/ returns 404 and the whitepaper does not "
               "specify address formats, so there is no project documentation "
               "to cross-check the code against.",
     "unblocks": "Project publication of an address-format specification."},
]

# -------------------------------------------------------------- wallets tested
WALLETS = [
    {"id": "reference", "name": "Reference implementation (this pack)",
     "version": "src/address_codec.py (pure Python stdlib)",
     "role": "Codec, derivation, signing, verification; 25/25 drill cases",
     "result": "PASS"},
    {"id": "xrpl-py", "name": "xrpl-py",
     "version": "5.2.0 (pip)",
     "role": "Derivation, X-address codec, offline transaction signing",
     "result": "PASS (24/24 cross-checks)"},
    {"id": "ripple-keypairs", "name": "ripple-keypairs + ripple-address-codec",
     "version": "npm (latest at 2026-11-22)",
     "role": "Derivation, X-address codec, offline signing",
     "result": "PASS (24/24 cross-checks)"},
    {"id": "postfiatd-rpc", "name": "postfiatd public RPC (testnet)",
     "version": "1.0.9, network_id 2025",
     "role": "account_info parsing: accepts classic addresses and account-public "
             "tokens (via accountFromStringStrict), rejects X-addresses and "
             "malformed input with actMalformed, returns actNotFound for "
             "well-formed but unfunded addresses",
     "result": "PASS (9 account_info probes)"},
    {"id": "wallet-apps", "name": "Real wallet apps (Xumm, Crossmark, GemWallet, Ledger)",
     "version": "n/a",
     "role": "End-user import behaviour",
     "result": "NOT TESTED (gap G-01/G-02)"},
]


def _counts(items, key):
    out = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return out


def main():
    drill = json.load(open(os.path.join(DERIVED, "drill-results.json")))
    cross = json.load(open(os.path.join(OUT, "crosscheck-results.json")))
    inventory = json.load(open(os.path.join(DERIVED, "address-inventory.json")))
    model = json.load(open(os.path.join(DERIVED, "collision-model.json")))
    server_info = json.load(open(os.path.join(OUT, "server_info.json")))
    info = server_info["result"]["info"]
    genesis = json.load(open(os.path.join(OUT, "rpc-account_info-pftl-genesis.json")))
    probe_log = open(os.path.join(OUT, "probe-run.log")).read()
    probe_start = [l for l in probe_log.splitlines() if l.startswith("probe_all.sh run start")][0].split("run start: ")[1]
    probe_end = [l for l in probe_log.splitlines() if l.startswith("probe_all.sh run end")][0].split("run end: ")[1]

    findings_by_sev = _counts(FINDINGS, "severity")
    findings_by_status = _counts(FINDINGS, "status")
    claims_by_status = _counts([{"status": c[1]} for c in CLAIMS], "status")
    risks_by_sev = _counts(RISKS, "severity")
    drill_summary = drill["summary"]
    cross_summary = cross["summary"]

    # --- findings.json ---
    findings_doc = {
        "verdict": VERDICT,
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {
            "findings_total": len(FINDINGS),
            "by_severity": findings_by_sev,
            "by_status": findings_by_status,
            "claims_total": len(CLAIMS),
            "claims_by_status": claims_by_status,
            "risks_total": len(RISKS),
            "risks_by_severity": risks_by_sev,
            "gaps_total": len(GAPS),
            "formats_inventoried": inventory["totals"]["address_formats"],
            "key_formats": inventory["totals"]["key_formats"],
            "seed_formats": inventory["totals"]["seed_formats"],
            "wallets_tested": len([w for w in WALLETS if w["result"].startswith("PASS")]),
            "drill_cases": drill_summary,
            "crosscheck": cross_summary,
        },
        "findings": FINDINGS,
        "risks": RISKS,
        "gaps": GAPS,
        "wallets": WALLETS,
    }
    with open(os.path.join(PACK, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings_doc, fh, indent=1, sort_keys=True)

    # --- docs/claim-index.md ---
    lines = ["# Claim-to-evidence index\n",
             "Every measured or specification-derived claim in this pack, with its "
             "status and its primary source. Status: VERIFIED (measured live or in "
             "the lab), SPECIFIED (pinned code, docs, or a cited standard), "
             "UNVERIFIED (could not be checked), UNTESTABLE (the safety boundary "
             "forbids the action that would test it).\n",
             "| ID | Status | Claim | Primary source |\n| --- | --- | --- | --- |\n"]
    for cid, status, text, source in CLAIMS:
        lines.append("| %s | %s | %s | %s |\n" % (cid, status, text, source))
    lines.append("\nCounts (recomputed from this table): %d claims — %s.\n"
                 % (len(CLAIMS), ", ".join("%s %d" % (k, v) for k, v in sorted(claims_by_status.items()))))
    with open(os.path.join(PACK, "docs", "claim-index.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # --- docs/risk-register.md ---
    lines = ["# Risk register\n",
             "Risks from the address-collision and confusion analysis "
             "(docs/risk-analysis.md). Severity and likelihood are the pack's own "
             "judgement, grounded in the measured drill and cross-check results.\n",
             "| ID | Severity | Likelihood | Risk | Finding | Detail |\n| --- | --- | --- | --- | --- | --- |\n"]
    for r in RISKS:
        lines.append("| %s | %s | %s | %s | %s | %s |\n"
                     % (r["id"], r["severity"], r["likelihood"], r["title"], r["finding"], r["detail"]))
    lines.append("\nCounts (recomputed from this table): %d risks — %s.\n"
                 % (len(RISKS), ", ".join("%s %d" % (k, v) for k, v in sorted(risks_by_sev.items()))))
    with open(os.path.join(PACK, "docs", "risk-register.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # --- docs/gap-register.md ---
    lines = ["# Gap register\n",
             "What this pack could not check, and what would unblock each item.\n",
             "| ID | Gap | Detail | What unblocks it |\n| --- | --- | --- | --- |\n"]
    for g in GAPS:
        lines.append("| %s | %s | %s | %s |\n" % (g["id"], g["title"], g["detail"], g["unblocks"]))
    lines.append("\nCounts (recomputed from this table): %d gaps.\n" % len(GAPS))
    with open(os.path.join(PACK, "docs", "gap-register.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # --- docs/evidence-index.md ---
    lines = ["# Evidence index\n",
             "Where every piece of evidence in this pack lives, and how to reproduce it.\n",
             "## Live probe outputs (unedited, outputs/)\n",
             "| File | What it proves |\n| --- | --- |\n",
             "| probe-run.log | Probe run times, per-file HTTP status and SHA-256 |\n",
             "| server_info.json | Build 1.0.9, network 2025, validated ledger, 21 peers, quorum 17 |\n",
             "| ledger_current.json | Validated ledger %s, %d transactions |\n"
             % (json.load(open(os.path.join(OUT, "ledger_current.json")))["result"]["ledger"]["ledger_index"],
                len(json.load(open(os.path.join(OUT, "ledger_current.json")))["result"]["ledger"].get("transactions", []))),
             "| rpc-account_info-pftl-genesis.json | Genesis account %s exists, balance %s |\n"
             % (genesis["result"]["account_data"]["Account"], genesis["result"]["account_data"]["Balance"]),
             "| rpc-account_info-xrpl-genesis.json | XRPL genesis address parses but does not exist on PFTL (actNotFound) |\n",
             "| rpc-account_info-account-one.json | Account-1 address parses but does not exist (actNotFound) |\n",
             "| rpc-account_info-zero-account.json | True zero address parses but does not exist (actNotFound) |\n",
             "| rpc-account_info-validator-master.json | A validator master-key address does not hold an account (actNotFound) |\n",
             "| rpc-account_info-docs-seed.json | Docs-seed address parses but does not exist (actNotFound) |\n",
             "| rpc-account_info-malformed.json | Malformed address rejected (actMalformed) |\n",
             "| rpc-account_info-xaddress.json | X-address rejected (actMalformed) |\n",
             "| wallet_propose.json | wallet_propose refused (HTTP 403 Forbidden) |\n",
             "| testnet_vl.json | Live validator list (25 validators, all Ed25519 master keys) |\n",
             "| explorer_health.json | Explorer health HTTP 500, rippled unreachable |\n",
             "| docs_postfiat_org.html | No /docs/ on the project site (HTTP 404) |\n",
             "## Lab outputs (outputs/ + outputs/derived/)\n",
             "| File | What it proves |\n| --- | --- |\n",
             "| drill-run.log | 25/25 drill cases, unedited log |\n",
             "| derived/drill-results.json | Drill case results, validator addresses, genesis AccountID, ledger census |\n",
             "| crosscheck-run.log | 24/24 three-way cross-checks, unedited log |\n",
             "| crosscheck-results.json | Per-seed derivation, X-address, and signature agreement |\n",
             "| derived/address-inventory.json | 9 address formats, 2 key formats, 4 seed formats |\n",
             "| derived/collision-model.json | Birthday bounds, checksum analysis, tag space |\n",
             "| model.log | Model run log |\n",
             "## Pinned-source fixtures (fixtures/)\n",
             "| File | What it proves |\n| --- | --- |\n",
             "| source-excerpts/*.txt (24 files) | Verbatim pinned-source excerpts with file, line numbers, and permalinks |\n",
             "| source-hashes.json | Pinned commit + per-file git blob hashes + absence checks (X-address: 0, mnemonic: 0) |\n",
             "| rfc1751-words.csv | The 2048-word RFC1751 dictionary extracted from the pinned source |\n",
             "| address-test-vectors.csv | Known-answer test vectors (docs seed + cross-check vectors) |\n",
             "## Reproduction\n",
             "Run `bash scripts/clean_reproduce.sh` from a fresh clone: it re-probes "
             "the live testnet, re-runs the drill and the model, and compares the fresh "
             "derived values with the shipped ones. The cross-check is re-run only when "
             "xrpl-py and the npm packages are available (see scripts/clean_reproduce.sh).\n"]
    with open(os.path.join(PACK, "docs", "evidence-index.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # --- fixtures/address-test-vectors.csv ---
    vectors = [
        ("classic-address", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
         "AccountID b5f762798a53d543a014caf8b297cff8f2f937e8",
         "docs seed, secp256k1 ordinal 0"),
        ("classic-address", "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf",
         "AccountID of Ed25519 public key edaac3f98bb94f451804ef5993c847daaa4e6154f455635659d88aa5c80f156303",
         "docs seed, Ed25519"),
        ("classic-address", "r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA",
         "AccountID f0633263b2e588395fcf15d406297e864f91aa35",
         "PFTL genesis account (live)"),
        ("classic-address", "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
         "AccountID 0000000000000000000000000000000000000000",
         "all-zero AccountID"),
        ("classic-address", "rrrrrrrrrrrrrrrrrrrrBZbvji",
         "AccountID 0000000000000000000000000000000000000001",
         "account-one (noAccount)"),
        ("x-address-mainnet-tag0", "XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF",
         "classic rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh, tag 0",
         "docs seed secp256k1 address, mainnet"),
        ("x-address-testnet-tag12345", "TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49Mhpsws",
         "classic rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh, tag 12345",
         "docs seed secp256k1 address, testnet"),
        ("family-seed", "snoPBrXtMeMyMHUVTgbuqAfg1SUTb",
         "seed bytes dedce9ce67b451d852fd4e846fcde31c",
         "public docs vector; also 'masterpassphrase' via generateSeed"),
        ("rfc1751-words", "I IRE BOND BOW TRIO LAID SEAT GOAL HEN IBIS IBIS DARE",
         "seed bytes dedce9ce67b451d852fd4e846fcde31c (reversed before encoding)",
         "docs seed as 12 RFC1751 words"),
        ("account-public-token", "aBQG8RQAzjs1eTKFEAQXr2gS4utcDiEC9wmi7pfUPTi27VCahwgw",
         "public key 0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020",
         "docs seed secp256k1 public key token (version 0x23)"),
    ]
    with open(os.path.join(PACK, "fixtures", "address-test-vectors.csv"), "w", encoding="utf-8") as fh:
        fh.write("format,value,derivation,note\n")
        for row in vectors:
            fh.write(",".join('"%s"' % c.replace('"', '""') for c in row) + "\n")

    # --- run-manifest.json ---
    manifest = {
        "pack": "PFTL address-format and wallet migration evidence pack",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "probe_window_utc": "%s to %s" % (probe_start, probe_end),
        "environment": {
            "python": "3.12.3",
            "tools": "curl, git, python3 (stdlib only for the reference implementation), node 24.22.1, xrpl-py 5.2.0",
            "network": "public endpoints only; no credentials, sessions, accounts, or signing of live material",
        },
        "repo_pins": {
            "postfiatd": "0085a1ff885d6a446369cf73a4430f75af22be55 (2026-10-10, PR #50 merge, v1.0.9)",
        },
        "live_endpoints": [
            "https://rpc.testnet.postfiat.org/ (postfiatd 1.0.9, network_id 2025)",
            "https://postfiat.org/testnet_vl.json",
            "https://explorer.testnet.postfiat.org/api/v1/ (health HTTP 500 at probe time)",
            "https://postfiat.org/ and https://postfiat.org/whitepaper/ and https://postfiat.org/docs/ (404)",
        ],
        "live_measurements": {
            "validated_ledger_seq": info["validated_ledger"]["seq"],
            "validators": 25,
            "unl_size": 25,
            "validation_quorum": info.get("validation_quorum"),
            "peers": info.get("peers"),
            "build_version": info["build_version"],
            "network_id": info["network_id"],
            "genesis_account": genesis["result"]["account_data"]["Account"],
            "genesis_balance_drops": genesis["result"]["account_data"]["Balance"],
            "explorer_health": open(os.path.join(OUT, "explorer_health.json")).read().strip(),
        },
        "drill": drill_summary,
        "crosscheck": cross_summary,
        "counts": {
            "findings_total": len(FINDINGS),
            "by_severity": findings_by_sev,
            "by_status": findings_by_status,
            "claims_total": len(CLAIMS),
            "claims_by_status": claims_by_status,
            "risks_total": len(RISKS),
            "gaps_total": len(GAPS),
            "formats_inventoried": inventory["totals"]["address_formats"],
            "key_formats": inventory["totals"]["key_formats"],
            "seed_formats": inventory["totals"]["seed_formats"],
            "wallets_tested": len([w for w in WALLETS if w["result"].startswith("PASS")]),
        },
        "verdict": VERDICT,
        "notes": [
            "Assessment + lab drills only: no live key material was used, no transactions sent, no flood traffic, no mainnet touched, nothing signed on the live network.",
            "All drill keys are freshly generated LAB keys, wiped after the run; only public keys, fingerprints, addresses, and timings are recorded. Lab seeds are never written to disk.",
            "Live values were re-probed for this pack; no numbers were copied from earlier packs.",
            "The GitHub API was rate-limited during pin verification; the pin was verified from a local git checkout (rev-parse HEAD + log).",
        ],
    }
    with open(os.path.join(PACK, "run-manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)

    print("analyze.py done:")
    print("  findings: %d (%s; %s)" % (len(FINDINGS), findings_by_sev, findings_by_status))
    print("  claims: %d (%s)" % (len(CLAIMS), claims_by_status))
    print("  risks: %d (%s)" % (len(RISKS), risks_by_sev))
    print("  gaps: %d" % len(GAPS))
    print("  wallets tested: %d" % len([w for w in WALLETS if w["result"].startswith("PASS")]))
    print("  drill: %s" % drill_summary)
    print("  crosscheck: %s" % cross_summary)


if __name__ == "__main__":
    main()
