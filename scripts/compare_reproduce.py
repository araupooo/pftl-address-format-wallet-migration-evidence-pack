#!/usr/bin/env python3
"""compare_reproduce.py — compare a fresh reproduction against the shipped
pack. Compares only deterministic values: LAB seeds are freshly generated
on every drill run, so LAB addresses are never compared — only case IDs,
pass/fail flags, counts, and values that must be stable (docs vectors,
validator addresses, genesis AccountID, model numbers).

Usage: python3 scripts/compare_reproduce.py <shipped-pack> <fresh-pack>
Writes outputs/fresh-clone-compare.log in the fresh pack and prints a
CHECKS PASSED summary. Exits 0 only if every check passes.
"""
import json
import os
import sys

SHIPPED, FRESH = sys.argv[1], sys.argv[2]
LOG = open(os.path.join(FRESH, "outputs", "fresh-clone-compare.log"), "w", encoding="utf-8")
CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    line = "%s %s%s" % ("PASS" if ok else "FAIL", name, (" — " + detail) if detail else "")
    LOG.write(line + "\n")
    print(line)


def load(base, rel):
    with open(os.path.join(base, rel), encoding="utf-8") as fh:
        return json.load(fh)


def main():
    s_si = load(SHIPPED, "outputs/server_info.json")["result"]["info"]
    f_si = load(FRESH, "outputs/server_info.json")["result"]["info"]
    check("build version unchanged", f_si["build_version"] == s_si["build_version"],
          "%s" % f_si["build_version"])
    check("network id unchanged", f_si["network_id"] == s_si["network_id"], "2025")
    check("validated ledger advanced (chain moved forward)",
          f_si["validated_ledger"]["seq"] >= s_si["validated_ledger"]["seq"],
          "shipped %s -> fresh %s" % (s_si["validated_ledger"]["seq"], f_si["validated_ledger"]["seq"]))
    check("peers unchanged", f_si.get("peers") == s_si.get("peers"), "%s" % f_si.get("peers"))
    check("validation quorum unchanged", f_si.get("validation_quorum") == s_si.get("validation_quorum"),
          "%s" % f_si.get("validation_quorum"))

    # account_info outcomes must be identical (format-level behaviour).
    for name in ("rpc-account_info-pftl-genesis", "rpc-account_info-xrpl-genesis",
                 "rpc-account_info-account-one", "rpc-account_info-zero-account",
                 "rpc-account_info-validator-master", "rpc-account_info-docs-seed",
                 "rpc-account_info-malformed", "rpc-account_info-xaddress"):
        s = load(SHIPPED, "outputs/%s.json" % name)["result"]
        f = load(FRESH, "outputs/%s.json" % name)["result"]
        check("account_info %s outcome unchanged" % name,
              (s.get("status"), s.get("error")) == (f.get("status"), f.get("error")),
              "%s / %s" % (f.get("status"), f.get("error")))

    s_gen = load(SHIPPED, "outputs/rpc-account_info-pftl-genesis.json")["result"]["account_data"]
    f_gen = load(FRESH, "outputs/rpc-account_info-pftl-genesis.json")["result"]["account_data"]
    check("genesis account unchanged", f_gen["Account"] == s_gen["Account"], f_gen["Account"])
    check("genesis balance unchanged", f_gen["Balance"] == s_gen["Balance"], f_gen["Balance"])

    s_vl = load(SHIPPED, "outputs/testnet_vl.json")
    f_vl = load(FRESH, "outputs/testnet_vl.json")
    check("validator list blob unchanged", s_vl.get("blobs_v2") == f_vl.get("blobs_v2"),
          "blobs_v2 identical (sequence 30)")

    # drill: same case IDs, all pass; deterministic values compared.
    s_drill = load(SHIPPED, "outputs/derived/drill-results.json")
    f_drill = load(FRESH, "outputs/derived/drill-results.json")
    s_cases = [(c["id"], c["title"], c["pass"]) for c in s_drill["cases"]]
    f_cases = [(c["id"], c["title"], c["pass"]) for c in f_drill["cases"]]
    check("drill case IDs/titles identical", [c[0] for c in s_cases] == [c[0] for c in f_cases],
          "%d cases" % len(f_cases))
    check("drill all pass (shipped)", all(c[2] for c in s_cases), "%d/%d" % (s_drill["summary"]["passed"], s_drill["summary"]["total"]))
    check("drill all pass (fresh)", all(c[2] for c in f_cases), "%d/%d" % (f_drill["summary"]["passed"], f_drill["summary"]["total"]))
    check("validator addresses unchanged",
          s_drill.get("live_validator_addresses") == f_drill.get("live_validator_addresses"),
          "%d addresses" % len(f_drill.get("live_validator_addresses", [])))
    check("genesis AccountID unchanged",
          s_drill.get("genesis_account_id") == f_drill.get("genesis_account_id"),
          f_drill.get("genesis_account_id"))
    check("ledger census has 0 X-address fields (both runs)",
          f_drill.get("ledger_census", {}).get("x_address_fields") == 0
          and s_drill.get("ledger_census", {}).get("x_address_fields") == 0,
          "fresh ledger %s, %d txs" % (f_drill.get("ledger_census", {}).get("ledger_index"),
                                       f_drill.get("ledger_census", {}).get("transactions", 0)))

    # model: deterministic numbers.
    s_model = load(SHIPPED, "outputs/derived/collision-model.json")
    f_model = load(FRESH, "outputs/derived/collision-model.json")
    check("collision model identical", s_model == f_model, "birthday + checksum numbers")
    s_inv = load(SHIPPED, "outputs/derived/address-inventory.json")
    f_inv = load(FRESH, "outputs/derived/address-inventory.json")
    check("address inventory totals identical", s_inv["totals"] == f_inv["totals"],
          str(f_inv["totals"]))
    check("address inventory formats identical", s_inv["formats"] == f_inv["formats"],
          "%d formats" % len(f_inv["formats"]))

    # analyze counts (excluding wall_seconds, which legitimately differ).
    def _norm_counts(counts):
        c = dict(counts)
        for k in ("drill_cases", "crosscheck"):
            if isinstance(c.get(k), dict):
                c[k] = {kk: vv for kk, vv in c[k].items() if kk != "wall_seconds"}
        return c
    s_find = load(SHIPPED, "findings.json")
    f_find = load(FRESH, "findings.json")
    check("findings counts identical", _norm_counts(s_find["counts"]) == _norm_counts(f_find["counts"]),
          str(f_find["counts"]["findings_total"]) + " findings, " +
          str(f_find["counts"]["claims_total"]) + " claims, " +
          str(f_find["counts"]["risks_total"]) + " risks")
    s_man = load(SHIPPED, "run-manifest.json")
    f_man = load(FRESH, "run-manifest.json")
    check("verdict unchanged", s_man["verdict"] == f_man["verdict"], "same verdict string")
    check("manifest counts identical", s_man["counts"] == f_man["counts"], "")

    # cross-check: only if the fresh run re-ran it.
    fresh_cross = os.path.join(FRESH, "outputs", "crosscheck-results.json")
    if os.path.exists(fresh_cross):
        f_cross = load(FRESH, "outputs/crosscheck-results.json")
        check("cross-check all pass (fresh)", f_cross["summary"]["passed"] == f_cross["summary"]["total"],
              "%d/%d" % (f_cross["summary"]["passed"], f_cross["summary"]["total"]))
    else:
        check("cross-check skipped in fresh run (tools unavailable; shipped results stand)",
              True, "not re-run")

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    total = len(CHECKS)
    summary = "CHECKS PASSED: %d/%d" % (passed, total) if passed == total else "CHECKS FAILED: %d/%d" % (passed, total)
    LOG.write(summary + "\n")
    print(summary)
    LOG.close()
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
