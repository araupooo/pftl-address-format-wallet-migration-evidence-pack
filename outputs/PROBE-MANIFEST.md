# Probe manifest

Read-only live probes for this pack. Probe window 2026-11-22 22:23:51–22:24:16 UTC.
Validated ledger seq 8,281,677. postfiatd 1.0.9, network_id 2025, state full,
21 peers, validation quorum 17.

## RPC calls (https://rpc.testnet.postfiat.org/, 17 POSTs)

| Method / account | Response |
| --- | --- |
| server_info | 200, build 1.0.9, network 2025 |
| ledger (validated 8281677, transactions) | 200, 0 transactions |
| ledger_closed | 200 |
| fee | 200 |
| feature | 200 |
| server_state | 200 |
| validators | 403 Forbidden |
| peers | 403 Forbidden |
| no_such_method | 200, unknownCmd (expected) |
| wallet_propose | 403 Forbidden |
| account_info r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA (PFTL genesis) | 200, success, balance 96999999999999880 |
| account_info r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59 (XRPL genesis) | 200, actNotFound |
| account_info rrrrrrrrrrrrrrrrrrrrBZbvji (account-one) | 200, actNotFound |
| account_info rrrrrrrrrrrrrrrrrrrrrhoLvTp (zero account) | 200, actNotFound |
| account_info rB4FqubLxGBCKcrFp6ZsTWiKqGKC6HqSuP (validator master) | 200, actNotFound |
| account_info rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh (docs seed) | 200, actNotFound |
| account_info rBADADDRESS00000000000000000000000000 (malformed) | 200, actMalformed |
| account_info XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF (X-address) | 200, actMalformed |

## HTTP GETs

| URL | Response |
| --- | --- |
| https://postfiat.org/testnet_vl.json | 200, 14781 B, 25 validators |
| https://explorer.testnet.postfiat.org/api/v1/health | 500, {"message":"rippled unreachable"} |
| https://explorer.testnet.postfiat.org/api/v1/metrics | 200, 108 B |
| https://postfiat.org/ | 200, 34713 B |
| https://postfiat.org/whitepaper/ | 200, 163089 B |
| https://postfiat.org/docs/ | 404 |

Total: 17 RPC POSTs + 6 GETs. No transactions submitted, no flood traffic.
