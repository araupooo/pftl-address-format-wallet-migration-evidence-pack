# Address formats

[FACT] All formats below were verified against the pinned postfiatd source
(commit `0085a1ff885d6a446369cf73a4430f75af22be55`), the reference
implementation in `src/address_codec.py`, and — where the format exists in
more than one implementation — three-way agreement across the reference
implementation, xrpl-py 5.2.0, and ripple-keypairs + ripple-address-codec
(24/24 cross-checks). Live behaviour was measured on the PFTL testnet
(network 2025, 2026-11-22 22:23 UTC, validated ledger seq 8,281,677).

## 1. Classic address

[FACT] A classic address is a Base58Check encoding of a 20-byte AccountID
with version byte `0x00` (TokenType::AccountID = 0,
`include/xrpl/protocol/tokens.h:42`). The encoding is
`<version><AccountID><checksum>`, where the checksum is the first 4 bytes
of the double-SHA-256 digest of `<version><AccountID>`
(`src/libxrpl/protocol/tokens.cpp:182-195, 325-342`). The alphabet is the
XRPL alphabet
`rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz`
(`tokens.cpp:143`) — not Bitcoin's alphabet. Classic addresses start with
`r`; the measured examples are 27–34 characters.

[FACT] Worked example (public docs vector): the secp256k1 public key
`0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020`
gives AccountID `b5f762798a53d543a014caf8b297cff8f2f937e8`, which encodes to
`rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh` (34 characters).

[FACT] The node accepts a classic address in `account_info` and returns the
account or `actNotFound` when the address is well-formed but unfunded
(measured live for the XRPL genesis address, the account-1 address, a
validator master-key address, and the docs-seed address). A malformed
classic address returns `actMalformed` (measured live).

[ANALYSIS] The classic address is the only address format the ledger and
the node understand. Everything else is a client-side convenience that
must be converted before it touches the node.

## 2. X-address (mainnet)

[FACT] An X-address is a Base58Check encoding of 31 bytes: a 2-byte prefix
`[0x05, 0x44]`, the 20-byte AccountID, a 1-byte flag (0 = no tag, 1 = tag),
a 4-byte little-endian destination tag, and 4 reserved zero bytes. The
format is specified by the client-side ripple-address-codec library; the
pinned node code contains no X-address support at all (0 matches for
`toXAddress`/`XAddress`/`xAddress` in `src/` + `include/`).

[FACT] Worked example: classic address
`rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh` with tag 0 encodes to
`XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF` (47 characters).
With no tag it encodes to
`XVPcpSm47b1CZkf5AkKM9a84dQHe3m4sBhsrA4XtnBECTAc`.

[FACT] The node rejects an X-address in `account_info` with `actMalformed`
(measured live). `doAccountInfo` parses the account with
`parseBase58<AccountID>` only (`src/xrpld/rpc/handlers/AccountInfo.cpp:74-83`).

## 3. X-address (testnet)

[FACT] Identical layout to the mainnet X-address, with prefix `[0x04, 0x93]`
instead of `[0x05, 0x44]`. This is the only address format in the pack that
distinguishes networks: classic addresses carry no network byte.

[FACT] Worked example: classic address
`rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh` with tag 12345 encodes to
`TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49Mhpsws` (47 characters).

## 4. AccountID (160-bit)

[FACT] The AccountID is `RIPEMD-160(SHA-256(public key))`, 20 bytes
(`src/libxrpl/protocol/AccountID.cpp:168-176`). It is the value that is
actually stored in the ledger; every address format is an encoding of it.

[FACT] Worked example: the PFTL genesis account
`r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA` has AccountID
`f0633263b2e588395fcf15d406297e864f91aa35` (measured live, drill D-12).

## 5. Family seed

[FACT] A family seed is a Base58Check encoding of a 16-byte seed with
version byte `0x21` (TokenType::FamilySeed = 33,
`include/xrpl/protocol/tokens.h:46`), starting with `s`
(`src/libxrpl/protocol/Seed.cpp:88-95`). The public docs vector is
`snoPBrXtMeMyMHUVTgbuqAfg1SUTb` (29 characters), seed bytes
`dedce9ce67b451d852fd4e846fcde31c`.

[FACT] A random seed is 16 bytes from the CSPRNG (`Seed.cpp:66-74`); a
passphrase seed is the first 16 bytes of SHA-512-Half of the passphrase
(`Seed.cpp:76-86`). Measured: `generateSeed("masterpassphrase")` reproduces
the docs seed exactly (drill D-03).

## 6. RFC1751 seed words

[FACT] A seed can be written as 12 words from a 2048-word dictionary
(`src/libxrpl/crypto/RFC1751.cpp:42`), 6 words per 64-bit half, each half
carrying a 2-bit parity (`RFC1751.cpp:301-330, 409-460`). The 16 seed bytes
are reversed before encoding (`Seed.cpp:135-145`).

[FACT] Worked example: the docs seed encodes to
`I IRE BOND BOW TRIO LAID SEAT GOAL HEN IBIS IBIS DARE` (drill D-05).
A corrupted word is rejected, and changing the last word to another valid
word is caught by the parity check (both measured in drill D-05).

## 7. Account public key token

[FACT] A public key can be written as a Base58Check token with version
byte `0x23` (TokenType::AccountPublic = 35, `tokens.h:43`), 33 bytes of key
material. Worked example: the docs seed's secp256k1 public key encodes to
`aBQG8RQAzjs1eTKFEAQXr2gS4utcDiEC9wmi7pfUPTi27VCahwgw` (52 characters).

[FACT] The node accepts an account-public token where an account is
expected: `accountFromStringStrict` maps it to its AccountID
(`src/xrpld/rpc/detail/RPCHelpers.cpp:44-60`). This is the one
non-classic-address form the RPC layer understands.

## 8. Account secret key token

[FACT] A secret key can be written as a Base58Check token with version byte
`0x22` (TokenType::AccountSecret = 34, `tokens.h:44`), 32 bytes of secret.
The token round-trips (drill D-15). [ANALYSIS] The value itself is never
recorded in this pack: a secret token decodes directly to the secret key,
and publishing one — even for a LAB key — would be poor hygiene.

## 9. Node public key token

[FACT] A validator/node public key is a Base58Check token with version byte
`0x1C` (TokenType::NodePublic = 28, `tokens.h:40`), 33 bytes. This is the
format validator public keys take in configuration and manifests; it is not
an account address and must not be used as one.

## Key formats (the two key types behind every address)

[FACT] KeyType has exactly two values: secp256k1 = 0, ed25519 = 1
(`include/xrpl/protocol/KeyType.h:28-31`). A public key is 33 bytes: an
Ed25519 key is `0xED` + 32 bytes; a secp256k1 key is `0x02`/`0x03` + the
32-byte x-coordinate (`src/libxrpl/protocol/PublicKey.cpp:224-236`).
The key type is detected from the first byte alone, which is why the same
seed yields two different accounts: the Ed25519 and secp256k1 public keys
differ, so their AccountIDs differ (finding F-01).

## Special addresses

[FACT] The all-zero AccountID encodes to `rrrrrrrrrrrrrrrrrrrrrhoLvTp`
(21 leading `r`s, 27 characters), verified against xrpl-py and the
reference implementation. The commonly quoted
`rrrrrrrrrrrrrrrrrrrrBZbvji` decodes to AccountID `0...01`
(`AccountID.cpp` `noAccount()`), not zero. Both return `actNotFound` on the
live testnet. The PFTL genesis account is the only one of the probed
special addresses that exists.

## Format summary

| # | Format | Encoding | Bytes | Chars (measured) |
| --- | --- | --- | --- | --- |
| 1 | Classic address | Base58Check 0x00 + AccountID | 25 | 27–34 |
| 2 | X-address (mainnet) | Base58Check 0x05 0x44 + AccountID + flag + tag + zeros | 35 | 47 |
| 3 | X-address (testnet) | Base58Check 0x04 0x93 + AccountID + flag + tag + zeros | 35 | 47 |
| 4 | AccountID | RIPEMD-160(SHA-256(pubkey)) | 20 | 40 (hex) |
| 5 | Family seed | Base58Check 0x21 + 16-byte seed | 21 | 29 |
| 6 | RFC1751 seed words | 12 words, 2-bit parity per half | 16 | 12 words |
| 7 | Account public token | Base58Check 0x23 + 33-byte key | 38 | 52 |
| 8 | Account secret token | Base58Check 0x22 + 32-byte secret | 37 | 51 |
| 9 | Node public token | Base58Check 0x1C + 33-byte key | 38 | 52 |

Counts (recomputed from this table): 9 address formats inventoried.
