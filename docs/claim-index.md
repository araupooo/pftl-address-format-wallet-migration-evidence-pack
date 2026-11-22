# Claim-to-evidence index
Every measured or specification-derived claim in this pack, with its status and its primary source. Status: VERIFIED (measured live or in the lab), SPECIFIED (pinned code, docs, or a cited standard), UNVERIFIED (could not be checked), UNTESTABLE (the safety boundary forbids the action that would test it).
| ID | Status | Claim | Primary source |
| --- | --- | --- | --- |
| C-01 | VERIFIED | A classic address is Base58Check(version 0x00, 20-byte AccountID). | AccountID.cpp:114-120; tokens.h:42; drill D-01/D-12; cross-check 24/24. |
| C-02 | VERIFIED | AccountID = RIPEMD-160(SHA-256(public key)). | AccountID.cpp:168-176; drill D-01/D-02; 3-way derivation agreement. |
| C-03 | VERIFIED | A family seed is Base58Check(version 0x21, 16-byte seed). | Seed.cpp:88-95; tokens.h:46; drill D-01/D-03. |
| C-04 | VERIFIED | A passphrase seed is SHA-512-Half(passphrase), first 16 bytes. | Seed.cpp:76-86; drill D-03: 'masterpassphrase' -> snoPBrXtMeMyMHUVTgbuqAfg1SUTb. |
| C-05 | VERIFIED | Ed25519 secret = SHA-512-Half(seed); public key = 0xED + 32 bytes. | SecretKey.cpp:309-327, 352-356; drill D-02; cross-check 24/24. |
| C-06 | VERIFIED | secp256k1 keypair = root key (SHA-512-Half(seed||seq)) + Generator tweak; ordinal 0 and 1 differ. | SecretKey.cpp:86-118, 145-223; drill D-01/D-07; cross-check 24/24. |
| C-07 | VERIFIED | X-address = Base58Check(prefix || AccountID || flag || tag LE || 4 zero bytes); main [0x05,0x44], test [0x04,0x93]. | ripple-address-codec encodeXAddress; drill D-04; cross-check 24/24. |
| C-08 | VERIFIED | The node rejects an X-address in account_info with actMalformed. | Live probe rpc-account_info-xaddress.json; AccountInfo.cpp:74-83. |
| C-09 | VERIFIED | The node rejects malformed classic addresses with actMalformed. | Live probe rpc-account_info-malformed.json. |
| C-10 | VERIFIED | A valid-format classic address with no account returns actNotFound (format validity does not imply existence). | Live probes: xrpl-genesis, account-one, validator-master, docs-seed. |
| C-11 | VERIFIED | The all-zero AccountID encodes to rrrrrrrrrrrrrrrrrrrrrhoLvTp (21 leading 'r's). | Reference implementation + xrpl-py agree; live probe returns actNotFound. |
| C-12 | VERIFIED | The 25 live testnet validator master keys map to 25 distinct valid classic addresses, all Ed25519. | Drill D-11 from outputs/testnet_vl.json. |
| C-13 | VERIFIED | The PFTL genesis account is r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA, AccountID f0633263b2e588395fcf15d406297e864f91aa35. | Live probe rpc-account_info-pftl-genesis.json; drill D-12. |
| C-14 | VERIFIED | Offline transaction signatures verify across implementations for both curves (byte-identical signatures). | Cross-check X-tx-*-sig, 8/8; drill D-09. |
| C-15 | VERIFIED | Verifying with the bare signing hash as the message fails for both curves; the serialized signing bytes verify. | Cross-check: verify(message=signing-hash)=False, verify(message=serialized-bytes)=True, both curves. |
| C-16 | VERIFIED | An RFC1751 seed is 12 words (6 per 64-bit half, 2-bit parity); a corrupted word or a parity flip is rejected. | Seed.cpp:135-145; RFC1751.cpp:409-460; drill D-05. |
| C-17 | VERIFIED | 12/12 malformed inputs are rejected by the reference codec (bad checksum, wrong version, bad character, tag overflow, 64-bit tag flag, wrong lengths, bad RFC1751 words). | Drill D-10. |
| C-18 | VERIFIED | Ed25519 passes RFC 8032 section 7.1 test vectors 1-3. | Drill D-14; scripts/ed25519_selftest.py. |
| C-19 | SPECIFIED | The pinned node code contains no X-address support (0 matches for toXAddress/XAddress/xAddress in src/ + include/). | fixtures/source-hashes.json absence_checks; extract_excerpts.py grep. |
| C-20 | SPECIFIED | The pinned node code contains no BIP39/mnemonic support (0 relevant matches in src/, include/, docs/). | fixtures/source-hashes.json absence_checks; extract_excerpts.py grep. |
| C-21 | SPECIFIED | KeyType has exactly two values: secp256k1 = 0, ed25519 = 1. | include/xrpl/protocol/KeyType.h:28-31. |
| C-22 | SPECIFIED | The Base58 alphabet is rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz (XRPL alphabet, not Bitcoin's). | src/libxrpl/protocol/tokens.cpp:143. |
| C-23 | SPECIFIED | The Base58Check checksum is the first 4 bytes of the double-SHA-256 digest of <type><token>. | src/libxrpl/protocol/tokens.cpp:182-195, 325-342 (code is authoritative; the comment is imprecise). |
| C-24 | VERIFIED | wallet_propose is refused by the public RPC proxy (HTTP 403 Forbidden). | Live probe outputs/wallet_propose.json. |
| C-25 | SPECIFIED | A destination tag is a 32-bit unsigned integer (0..2^32-1); larger values are rejected. | ripple-address-codec encodeXAddress; drill D-10 tag-overflow rejection. |
| C-26 | SPECIFIED | The secp256k1 Generator tweak uses a uint32 sequence and a uint32 sub-sequence counter (up to 128 attempts each). | SecretKey.cpp:145-175. |
| C-27 | SPECIFIED | Ed25519 derivation has no ordinal family: one seed gives exactly one Ed25519 keypair. | SecretKey.cpp:330-372 (generateKeyPair ignores ordinal for Ed25519). |
| C-28 | VERIFIED | Account-public (0x23) and account-secret (0x22) Base58Check tokens round-trip. | Drill D-15; tokens.h:43-44. |
| C-29 | UNVERIFIED | Real wallet apps (Xumm, Crossmark, GemWallet, Ledger) import a PFTL family seed to the same address as the reference implementation. | No wallet app could be installed and driven in this lab; see gap G-01. |
| C-30 | UNVERIFIED | Whether any existing mainnet wallet defaults to Ed25519 or secp256k1 for a new PFTL account. | No mainnet exists and no wallet survey was possible; see gap G-04. |
| C-31 | UNTESTABLE | A BIP44 (44'/144'/0'/0/0) derivation of a PFTL mnemonic produces the same address as the family-seed derivation of the same entropy. | Would need a hardware wallet and its mnemonic; the safety boundary forbids real key material; see gap G-02. |
| C-32 | UNTESTABLE | A classic address created on the testnet today will be valid at mainnet genesis. | No mainnet exists and no 1:1 conversion mechanism is established; see gap G-04. |

Counts (recomputed from this table): 32 claims — SPECIFIED 8, UNTESTABLE 2, UNVERIFIED 2, VERIFIED 20.
