# Address-collision and confusion risk analysis

## Collision analysis (hash space)

[FACT] An AccountID is 160 bits. The collision probability among `n`
uniformly drawn accounts is approximately `n(n-1) / 2^161` (birthday
bound), computed in `src/address_model.py` and recorded in
`outputs/derived/collision-model.json`:

| Accounts | Collision probability |
| --- | --- |
| 1,000,000 | ~3.4e-37 |
| 1,000,000,000 | ~3.4e-31 |
| 1,000,000,000,000 | ~3.4e-25 |
| 2^80 (~1.2e24) | ~0.39 |

[ANALYSIS] Accidental AccountID collision is not a realistic risk: even a
billion accounts collide with probability ~3.4e-31. The same math for the
128-bit seed space gives ~1.5e-27 at a million seeds and ~1.5e-21 at a
billion seeds. The birthday bound only bites at ~2^80 accounts (or ~2^64
seeds), which is not a scale any ledger reaches.

## Checksum analysis (typo resistance)

[FACT] The Base58Check checksum is 32 bits. [ESTIMATE] Assuming the
checksum is uniform over random corruptions, a random single-character
corruption of an address goes undetected with probability 2^-32. A
34-character classic address has 34 x 57 = 1,938 single-character
corruptions, of which ~4.5e-7 are expected to pass the checksum. The drill
measured 12/12 malformed inputs rejected, including a bad checksum — but
that is a correctness check, not a measurement of the 2^-32 rate, which
cannot be measured by sampling.

[ANALYSIS] The checksum is a typo detector, not a guarantee. Copy-paste and
QR codes, not retyping, are the practical mitigation; the residual risk is
negligible per address and non-zero across a large user base.

## Confusion analysis (the real risks)

The collision math says the hash space is safe. The confusion risks are
all encoding-level — same key material, different representation — and they
were all measured in the drill or the cross-check:

**Same seed, different curve (R-01, HIGH).** [FACT] One seed derives two
different accounts: Ed25519 and secp256k1 give different public keys, hence
different AccountIDs, hence different addresses. Measured for the docs seed
and 3 LAB seeds (drill D-08). A wallet that defaults to the other curve
shows an empty account. Recovery is possible (derive the other curve from
the same seed), but only if the user knows the other curve exists.

**Same key, different encoding (R-02, HIGH).** [FACT] One AccountID has
many encodings: classic address, mainnet X-address, testnet X-address, hex,
and (for the public key) the account-public token. The encodings are not
interchangeable at the node: the node accepts the classic address and the
account-public token, and rejects X-addresses with `actMalformed`. A
migration that stores the wrong encoding breaks loudly at the RPC layer.

**Same address, different network (R-03, HIGH).** [FACT] Classic addresses
carry no network byte, so the same address is valid on testnet and mainnet.
Measured: the XRPL genesis address parses on the PFTL testnet and simply
does not exist there. Only X-addresses distinguish networks, and the node
does not accept them — so the network must be carried out-of-band in every
payment flow.

**Same seed, different ordinal (R-06, MEDIUM).** [FACT] A secp256k1 seed
holds many accounts (ordinals); an Ed25519 seed holds one. Measured:
ordinal 0 vs 1 differ for every LAB seed (drill D-07). A migration that
assumes one account per seed strands ordinal-1+ accounts.

**Same seed, different serialization (R-08, MEDIUM).** [FACT] One seed has
four serializations (family seed, 12 words, hex, passphrase). Three are
lossless conversions of the same 16 bytes; the passphrase is a different
secret that derives a seed. `parseGenericSeed` accepts all of them, and a
passphrase that happens to look like a seed is treated as one
(`Seed.cpp:97-133`).

**Same account, missing tag (R-04, MEDIUM).** [FACT] The destination tag
exists only in X-addresses. Converting an X-address to a classic address
drops the tag silently; the ledger cannot recover it.

## Risk summary

Counts (recomputed from `docs/risk-register.md`): 14 risks — 3 HIGH,
6 MEDIUM, 4 LOW, 1 INFO. The three HIGH risks are all confusion risks
(R-01 curve, R-02 X-address, R-03 network), not collision risks. The full
register with likelihoods and remediation pointers is in
`docs/risk-register.md`.
