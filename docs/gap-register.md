# Gap register
What this pack could not check, and what would unblock each item.
| ID | Gap | Detail | What unblocks it |
| --- | --- | --- | --- |
| G-01 | Real wallet apps not tested | Xumm, Crossmark, GemWallet, and other wallet apps could not be installed and driven in this lab. Import behaviour is verified only for three libraries (reference, xrpl-py, ripple-keypairs). | A device lab or emulator run importing a LAB family seed into each app. |
| G-02 | Hardware-wallet / BIP44 derivation not tested | Whether a Ledger-style BIP44 (44'/144') derivation of a mnemonic matches the family-seed derivation could not be tested: it needs a hardware wallet and real key material, which the safety boundary forbids. | A hardware-wallet test with LAB-only mnemonics in a lab harness. |
| G-03 | No on-ledger transaction sample in the probe window | The validated ledger at probe time held 0 transactions, so the on-ledger address census is vacuous. The claim that only classic addresses appear on-ledger rests on the code (X-addresses are client-side), not on a transaction sample. | Re-run the census over a busier ledger window. |
| G-04 | No mainnet to test address validity against | There is no mainnet and no established 1:1 testnet-to-mainnet conversion, so mainnet address validity and cross-network behaviour cannot be measured, only reasoned about from the format (no network byte). | A mainnet launch or a published conversion specification. |
| G-05 | Codec test-suite vectors not fetched from upstream | The ripple-address-codec repository's own test-vector files returned 404 at the guessed paths (the repo moved into the xrpl.js monorepo). X-address vectors are instead verified by three-way agreement of independent implementations. | Locate the vectors in the xrpl.js monorepo and add them as a fourth check. |
| G-06 | GitHub API rate-limited during pin verification | The unauthenticated GitHub API returned 'rate limit exceeded' for the shared egress IP while verifying the pinned commit, so the pin was verified from a local git checkout (rev-parse HEAD plus log) instead of the API. | An authenticated API call, or a fresh clone at the pinned commit. |
| G-07 | No project documentation for address formats | postfiat.org/docs/ returns 404 and the whitepaper does not specify address formats, so there is no project documentation to cross-check the code against. | Project publication of an address-format specification. |

Counts (recomputed from this table): 7 gaps.
