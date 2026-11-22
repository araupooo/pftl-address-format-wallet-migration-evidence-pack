#!/bin/bash
# probe_all.sh — re-probe every live public endpoint used by this pack and
# retain the unedited responses under outputs/.
#
# Usage: bash scripts/probe_all.sh [OUTPUT_DIR]
#   OUTPUT_DIR defaults to outputs/ relative to the pack root.
# No credentials, sessions, or accounts are used. All endpoints are public.
#
# SAFETY BOUNDARY (non-negotiable, see docs/methodology.md): BOUNDED
# OBSERVATION ONLY. This script performs read-only queries only. It sends no
# transactions, no flood traffic, and no load of any kind to the shared
# testnet. Total RPC calls: under 20, each a single read-only request.
set -u
PACK_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$PACK_ROOT/outputs}"
mkdir -p "$OUT"
LOG="$OUT/probe-run.log"
: > "$LOG"
log() { echo "$*" | tee -a "$LOG"; }
sha() { sha256sum "$1" | awk '{print $1}'; }

log "probe_all.sh run start: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
log "pack root: $PACK_ROOT"
log "safety boundary: read-only queries only; no transactions, no flood traffic"

RPC="https://rpc.testnet.postfiat.org/"
post() { # $1 outfile $2 method-json
  curl -s -m 30 -X POST "$RPC" -H 'Content-Type: application/json' -d "$2" \
    -o "$OUT/$1" -w "%{http_code} %{time_total}s" > "$OUT/$1.http" 2>&1
  log "$1 -> $(cat "$OUT/$1.http") sha256=$(sha "$OUT/$1")"
  rm -f "$OUT/$1.http"
}
get() { # $1 url $2 outfile
  curl -s -m 30 "$1" -o "$OUT/$2" -w "%{http_code} %{time_total}s %{size_download}B" > "$OUT/$2.http" 2>&1
  log "$2 -> $(cat "$OUT/$2.http") sha256=$(sha "$OUT/$2")"
  rm -f "$OUT/$2.http"
}

# --- postfiatd JSON-RPC (public proxy) ---
post server_info.json '{"method":"server_info","params":[{}]}'
VALIDATED_SEQ="$(python3 -c "import json;print(json.load(open('$OUT/server_info.json'))['result']['info']['validated_ledger']['seq'])")"
log "validated seq for numeric ledger fetch: $VALIDATED_SEQ"
post ledger_current.json "{\"method\":\"ledger\",\"params\":[{\"ledger_index\":$VALIDATED_SEQ,\"transactions\":true,\"expand\":false}]}"
post ledger_closed.json '{"method":"ledger_closed","params":[{}]}'
post fee.json '{"method":"fee","params":[{}]}'
post feature_list.json '{"method":"feature","params":[{}]}'
post server_state.json '{"method":"server_state","params":[{}]}'
# Admin-gated methods: the public proxy is expected to refuse these; the
# refusal body itself is the evidence and is kept unedited.
post validators.json '{"method":"validators","params":[{}]}'
post peers.json '{"method":"peers","params":[{}]}'
post invalid_method.json '{"method":"no_such_method","params":[{}]}'
# wallet_propose is an admin method in rippled: the public proxy is expected
# to refuse it. The refusal (or, if answered, the derived address) is the
# evidence for whether the node itself can propose wallets.
post wallet_propose.json '{"method":"wallet_propose","params":[{}]}'

# --- Address-format evidence on the live ledger ---
# PFTL genesis account (classic address, known from the public ledger).
post rpc-account_info-pftl-genesis.json '{"method":"account_info","params":[{"account":"r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA","ledger_index":"validated"}]}'
# XRPL genesis account: a classic address that does NOT exist on PFTL.
# actNotFound proves addresses are ledger-scoped, not globally meaningful.
post rpc-account_info-xrpl-genesis.json '{"method":"account_info","params":[{"account":"r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59","ledger_index":"validated"}]}'
# The all-zero account (classic address of the zero AccountID).
# NOTE: rrrrrrrrrrrrrrrrrrrrBZbvji is NOT the zero account — it decodes to
# AccountID 0...01 (AccountID.cpp noAccount()); the true zero address is
# rrrrrrrrrrrrrrrrrrrrrhoLvTp (verified against xrpl-py + the reference
# implementation). Both are probed; neither is expected to exist on PFTL.
post rpc-account_info-account-one.json '{"method":"account_info","params":[{"account":"rrrrrrrrrrrrrrrrrrrrBZbvji","ledger_index":"validated"}]}'
post rpc-account_info-zero-account.json '{"method":"account_info","params":[{"account":"rrrrrrrrrrrrrrrrrrrrrhoLvTp","ledger_index":"validated"}]}'
# A live validator's master-key classic address (derived in the drill from
# the VL). Validators' master keys are identities, not funded accounts.
post rpc-account_info-validator-master.json '{"method":"account_info","params":[{"account":"rB4FqubLxGBCKcrFp6ZsTWiKqGKC6HqSuP","ledger_index":"validated"}]}'
# The public docs-seed secp256k1 address: valid format, unfunded on PFTL.
post rpc-account_info-docs-seed.json '{"method":"account_info","params":[{"account":"rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","ledger_index":"validated"}]}'
# A malformed classic address: the node must reject it, not answer it.
post rpc-account_info-malformed.json '{"method":"account_info","params":[{"account":"rBADADDRESS00000000000000000000000000","ledger_index":"validated"}]}'
# An X-address sent where a classic address is expected: the node must
# reject it (X-addresses are client-side only; the ledger has no tag field
# for them in account_info).
post rpc-account_info-xaddress.json '{"method":"account_info","params":[{"account":"XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF","ledger_index":"validated"}]}'

# --- Validator list (the live UNL publisher document) ---
get "https://postfiat.org/testnet_vl.json" testnet_vl.json

# --- Explorer (expected: API may be degraded; HTTP status is the evidence) ---
get "https://explorer.testnet.postfiat.org/api/v1/health" explorer_health.json
get "https://explorer.testnet.postfiat.org/api/v1/metrics" explorer_metrics.json

# --- Project site + docs (address / wallet documentation) ---
get "https://postfiat.org/" postfiat_org.html
get "https://postfiat.org/whitepaper/" postfiat_whitepaper.html
get "https://postfiat.org/docs/" docs_postfiat_org.html

log "probe_all.sh run end: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
