# Evidence index
Where every piece of evidence in this pack lives, and how to reproduce it.
## Live probe outputs (unedited, outputs/)
| File | What it proves |
| --- | --- |
| probe-run.log | Probe run times, per-file HTTP status and SHA-256 |
| server_info.json | Build 1.0.9, network 2025, validated ledger, 21 peers, quorum 17 |
| ledger_current.json | Validated ledger 8281677, 0 transactions |
| rpc-account_info-pftl-genesis.json | Genesis account r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA exists, balance 96999999999999880 |
| rpc-account_info-xrpl-genesis.json | XRPL genesis address parses but does not exist on PFTL (actNotFound) |
| rpc-account_info-account-one.json | Account-1 address parses but does not exist (actNotFound) |
| rpc-account_info-zero-account.json | True zero address parses but does not exist (actNotFound) |
| rpc-account_info-validator-master.json | A validator master-key address does not hold an account (actNotFound) |
| rpc-account_info-docs-seed.json | Docs-seed address parses but does not exist (actNotFound) |
| rpc-account_info-malformed.json | Malformed address rejected (actMalformed) |
| rpc-account_info-xaddress.json | X-address rejected (actMalformed) |
| wallet_propose.json | wallet_propose refused (HTTP 403 Forbidden) |
| testnet_vl.json | Live validator list (25 validators, all Ed25519 master keys) |
| explorer_health.json | Explorer health HTTP 500, rippled unreachable |
| docs_postfiat_org.html | No /docs/ on the project site (HTTP 404) |
## Lab outputs (outputs/ + outputs/derived/)
| File | What it proves |
| --- | --- |
| drill-run.log | 25/25 drill cases, unedited log |
| derived/drill-results.json | Drill case results, validator addresses, genesis AccountID, ledger census |
| crosscheck-run.log | 24/24 three-way cross-checks, unedited log |
| crosscheck-results.json | Per-seed derivation, X-address, and signature agreement |
| derived/address-inventory.json | 9 address formats, 2 key formats, 4 seed formats |
| derived/collision-model.json | Birthday bounds, checksum analysis, tag space |
| model.log | Model run log |
## Pinned-source fixtures (fixtures/)
| File | What it proves |
| --- | --- |
| source-excerpts/*.txt (24 files) | Verbatim pinned-source excerpts with file, line numbers, and permalinks |
| source-hashes.json | Pinned commit + per-file git blob hashes + absence checks (X-address: 0, mnemonic: 0) |
| rfc1751-words.csv | The 2048-word RFC1751 dictionary extracted from the pinned source |
| address-test-vectors.csv | Known-answer test vectors (docs seed + cross-check vectors) |
## Reproduction
Run `bash scripts/clean_reproduce.sh` from a fresh clone: it re-probes the live testnet, re-runs the drill and the model, and compares the fresh derived values with the shipped ones. The cross-check is re-run only when xrpl-py and the npm packages are available (see scripts/clean_reproduce.sh).
