# Citations

Pinned postfiatd commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10, PR #50 merge, v1.0.9). Base permalink:
`https://github.com/postfiatorg/postfiatd/blob/0085a1ff885d6a446369cf73a4430f75af22be55/`

Verbatim excerpts of every citation below live in
`fixtures/source-excerpts/` with file, lines, and permalink. Line numbers
were verified with `grep -n` on a local checkout of the pinned commit.

## Address and seed formats (pinned postfiatd source)

| Claim | Source | Lines |
| --- | --- | --- |
| Token-type version bytes (AccountID 0, FamilySeed 33, AccountPublic 35, AccountSecret 34, NodePublic 28, NodePrivate 32) | `include/xrpl/protocol/tokens.h` | 38–46 |
| XRPL Base58 alphabet | `src/libxrpl/protocol/tokens.cpp` | 143 |
| Base58Check checksum (first 4 bytes of double-SHA-256) | `src/libxrpl/protocol/tokens.cpp` | 182–195 |
| Base58Check layout `<type><token><checksum>` | `src/libxrpl/protocol/tokens.cpp` | 325–342 |
| `randomSeed` / `generateSeed` | `src/libxrpl/protocol/Seed.cpp` | 66–86 |
| `parseBase58<Seed>` (FamilySeed, 16 bytes) | `src/libxrpl/protocol/Seed.cpp` | 88–95 |
| `parseGenericSeed` (hex / family seed / RFC1751 / passphrase fallback) | `src/libxrpl/protocol/Seed.cpp` | 97–133 |
| `seedAs1751` (reverse bytes, RFC1751-encode) | `src/libxrpl/protocol/Seed.cpp` | 135–145 |
| `deriveDeterministicRootKey` (SHA-512-Half(seed \|\| seq)) | `src/libxrpl/protocol/SecretKey.cpp` | 86–118 |
| Generator `calculateTweak` | `src/libxrpl/protocol/SecretKey.cpp` | 145–175 |
| `generateSecretKey` (Ed25519 = SHA-512-Half(seed)) | `src/libxrpl/protocol/SecretKey.cpp` | 309–327 |
| `generateKeyPair` / `derivePublicKey` (0xED prefix) | `src/libxrpl/protocol/SecretKey.cpp` | 330–372 |
| `sign()` (Ed25519 direct; secp256k1 over SHA-512-Half) | `src/libxrpl/protocol/SecretKey.cpp` | 258–307 |
| `publicKeyType` (0xED / 0x02 / 0x03) | `src/libxrpl/protocol/PublicKey.cpp` | 224–236 |
| `toBase58` / `parseBase58<AccountID>` | `src/libxrpl/protocol/AccountID.cpp` | 114–131 |
| `calcAccountID` (RIPEMD-160(SHA-256)); `xrpAccount()` zero; `noAccount()` 1 | `src/libxrpl/protocol/AccountID.cpp` | 168–190 |
| KeyType enum (secp256k1 = 0, ed25519 = 1) | `include/xrpl/protocol/KeyType.h` | 28–31 |
| RFC1751 dictionary (2048 words) | `src/libxrpl/crypto/RFC1751.cpp` | 42 |
| RFC1751 `btoe` (8 bytes -> 6 words, 2-bit parity) | `src/libxrpl/crypto/RFC1751.cpp` | 301–330 |
| RFC1751 `etob` (parity check, -2 on failure) | `src/libxrpl/crypto/RFC1751.cpp` | 409–460 |
| RFC1751 `getKeyFromEnglish` / `getEnglishFromKey` | `src/libxrpl/crypto/RFC1751.cpp` | 463–504 |
| `getSigningHash` (SHA-512-Half of prefix + serialized object) | `src/libxrpl/protocol/STObject.cpp` | 418–425 |
| `doAccountInfo` parses with `parseBase58<AccountID>` only | `src/xrpld/rpc/handlers/AccountInfo.cpp` | 74–83 |
| `accountFromStringStrict` (account-public token -> AccountID) | `src/xrpld/rpc/detail/RPCHelpers.cpp` | 44–70 |

## Absence evidence (pinned postfiatd source)

| Claim | Check |
| --- | --- |
| No X-address support in the node | `grep -rn toXAddress/XAddress/xAddress src/ include/` = 0 matches |
| No BIP39/mnemonic support in the node | `grep -rni mnemonic/bip39 src/ include/ docs/` = 0 relevant matches |

## Client-side format specifications

| Claim | Source |
| --- | --- |
| X-address layout and prefixes (main `[0x05, 0x44]`, test `[0x04, 0x93]`) | ripple-address-codec `encodeXAddress` / `decodeXAddress` (npm package source, read from the installed package) |
| secp256k1 signing (SHA-512-Half, RFC 6979, DER, low-S) | ripple-keypairs secp256k1 scheme (npm package source) |
| Ed25519 signing (message signed directly) | ripple-keypairs ed25519 scheme (npm package source) |

## Standards

| Claim | Source |
| --- | --- |
| Ed25519 test vectors 1–3 | RFC 8032, section 7.1 |
| RFC1751 word encoding and parity | RFC 1751 |
| Deterministic ECDSA nonces | RFC 6979 |
| BIP44 coin type 144 for XRP (mnemonic discussion only) | BIP-44 |

## Live measurements

| Claim | Source |
| --- | --- |
| Validated ledger 8,281,677; build 1.0.9; network 2025; 21 peers; quorum 17 | `outputs/server_info.json` (2026-11-22 22:23 UTC) |
| Genesis account, balance, AccountID | `outputs/rpc-account_info-pftl-genesis.json` |
| X-address / malformed -> `actMalformed`; unfunded -> `actNotFound` | `outputs/rpc-account_info-*.json` |
| `wallet_propose` -> HTTP 403 | `outputs/wallet_propose.json` |
| 25 validators, all Ed25519 master keys | `outputs/testnet_vl.json` |
| Explorer health HTTP 500 | `outputs/explorer_health.json` |
| `/docs/` HTTP 404 | `outputs/docs_postfiat_org.html` |
