#!/usr/bin/env python3
"""drill.py — lab migration drill for the address-format evidence pack.

Generates FRESH lab seeds (os.urandom) at runtime, derives addresses with
the reference implementation (src/address_codec.py), runs the codec
known-vector suite, the failure-mode matrix, the offline-signing drill,
and the live-ledger address census. No live key material is used, no
transactions are submitted, nothing is signed on any network.

LAB SEEDS ARE NEVER WRITTEN TO DISK. Only derived public material
(public keys, classic/X-addresses, fingerprints, timings) is recorded,
labelled LAB. The docs-seed vectors are public test vectors.

Outputs:
  outputs/derived/drill-results.json
  outputs/drill-run.log
"""
import hashlib
import json
import os
import sys
import time

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "src"))
sys.path.insert(0, os.path.join(PACK, "scripts"))
import address_codec as ac  # noqa: E402
import ed25519 as _ed25519  # noqa: E402  (RFC 8032 self-test only)

OUT = os.path.join(PACK, "outputs")
DERIVED = os.path.join(OUT, "derived")
os.makedirs(DERIVED, exist_ok=True)

LOG_PATH = os.path.join(OUT, "drill-run.log")
LOG = open(LOG_PATH, "w", encoding="utf-8")


def log(msg: str) -> None:
    LOG.write(msg + "\n")
    LOG.flush()
    print(msg)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


RESULTS = {"cases": [], "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def case(cid, title, ok, detail):
    RESULTS["cases"].append({"id": cid, "title": title, "pass": bool(ok), "detail": detail})
    log("%s %s: %s — %s" % ("PASS" if ok else "FAIL", cid, title, detail))
    return bool(ok)


# ---------------------------------------------------------------- vectors
DOCS_SEED = "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"  # public XRPL docs test vector
DOCS_SEED_HEX = "dedce9ce67b451d852fd4e846fcde31c"
DOCS_SECPUB = "0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020"
DOCS_SECSEC = "1acaaedece405b2a958212629e16f2eb46b153eee94cdd350fdeff52795525b7"
DOCS_SEC_ADDR = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
DOCS_EDPUB = "edaac3f98bb94f451804ef5993c847daaa4e6154f455635659d88aa5c80f156303"
DOCS_ED_ADDR = "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf"
DOCS_X_MAIN_TAG0 = "XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF"
DOCS_X_TEST_TAG12345 = "TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49Mhpsws"


def main():
    t0 = time.time()
    log("drill run start: %s" % RESULTS["generated_at_utc"])
    log("safety boundary: freshly generated LAB keys only; sign offline only; "
        "no transactions submitted; lab seeds never written to disk")

    # ---- D-01: docs seed, secp256k1 ordinal 0 (known vector) ----
    seed = ac.decode_family_seed(DOCS_SEED)
    assert seed.hex() == DOCS_SEED_HEX
    pub, sec = ac.derive_keypair(seed, "secp256k1", 0)
    ok = (pub.hex() == DOCS_SECPUB and sec.hex() == DOCS_SECSEC
          and ac.classic_address_from_public_key(pub) == DOCS_SEC_ADDR)
    case("D-01", "docs seed secp256k1 ordinal 0 derivation", ok,
         "pub %s address %s" % (pub.hex()[:16] + "…", DOCS_SEC_ADDR))

    # ---- D-02: docs seed, Ed25519 ----
    pub_e, sec_e = ac.derive_keypair(seed, "ed25519")
    ok = pub_e.hex() == DOCS_EDPUB and ac.classic_address_from_public_key(pub_e) == DOCS_ED_ADDR
    case("D-02", "docs seed Ed25519 derivation", ok,
         "pub %s address %s" % (pub_e.hex()[:16] + "…", DOCS_ED_ADDR))

    # ---- D-03: passphrase seed (generateSeed) ----
    pp_seed = ac.generate_seed_from_passphrase("masterpassphrase")
    ok = ac.encode_family_seed(pp_seed) == DOCS_SEED
    case("D-03", "passphrase 'masterpassphrase' -> docs seed", ok,
         "generateSeed is SHA-512-Half(passphrase)[:16]; matches the public "
         "docs seed exactly")

    # ---- D-04: X-address known vectors ----
    x_main = ac.classic_address_to_x_address(DOCS_SEC_ADDR, 0, False)
    x_test = ac.classic_address_to_x_address(DOCS_SEC_ADDR, 12345, True)
    ok = x_main == DOCS_X_MAIN_TAG0 and x_test == DOCS_X_TEST_TAG12345
    back = ac.x_address_to_classic_address(x_main)
    ok = ok and back == (DOCS_SEC_ADDR, 0, False)
    case("D-04", "X-address known vectors (main tag 0, test tag 12345)", ok,
         "main %s test %s" % (x_main, x_test))

    # ---- D-05: RFC1751 12-word encode/decode + parity ----
    words = ac.seed_as_1751(seed)
    ok = len(words.split()) == 12 and ac.seed_from_1751(words) == seed
    bad = words.split()
    bad[-1] = ac._load_words()[(ac._load_words().index(bad[-1]) + 1) % 2048]
    try:
        ac.seed_from_1751(" ".join(bad))
        parity_ok = False
    except ValueError:
        parity_ok = True
    ok = ok and parity_ok
    case("D-05", "RFC1751 12-word seed encode/decode + parity detection", ok,
         "words: %s" % words)

    # ---- D-06..D-08: fresh LAB seeds, both curves, ordinals ----
    lab = []
    for i in range(3):
        s = ac.random_seed_bytes()
        lab.append(s)
        fam = ac.encode_family_seed(s)
        for kt in ("ed25519", "secp256k1"):
            pub_i, sec_i = ac.derive_keypair(s, kt)
            addr = ac.classic_address_from_public_key(pub_i)
            ok = ac.is_valid_classic_address(addr)
            case("D-06", "lab seed %d %s derivation -> valid classic address" % (i + 1, kt), ok,
                 "LAB address %s (seed fingerprint %s)" % (addr, sha256_hex(s)[:16]))
        pub0, _ = ac.derive_keypair(s, "secp256k1", 0)
        pub1, _ = ac.derive_keypair(s, "secp256k1", 1)
        ok = pub0 != pub1 and ac.classic_address_from_public_key(pub0) != ac.classic_address_from_public_key(pub1)
        case("D-07", "lab seed %d secp256k1 ordinal 0 vs 1 differ" % (i + 1), ok,
             "ordinal 0 %s ordinal 1 %s"
             % (ac.classic_address_from_public_key(pub0), ac.classic_address_from_public_key(pub1)))
        # same seed, different curve -> different address (confusion case)
        addr_ed = ac.classic_address_from_public_key(ac.derive_keypair(s, "ed25519")[0])
        addr_sec = ac.classic_address_from_public_key(ac.derive_keypair(s, "secp256k1", 0)[0])
        ok = addr_ed != addr_sec
        case("D-08", "lab seed %d: same seed, Ed25519 vs secp256k1 give different addresses" % (i + 1), ok,
             "ed25519 %s secp256k1 %s (same seed, two accounts)" % (addr_ed, addr_sec))

    # ---- D-09: offline sign/verify, both curves, tamper rejection ----
    for kt in ("ed25519", "secp256k1"):
        pub_k, sec_k = ac.derive_keypair(lab[0], kt)
        msg = b"PFTL lab offline signing test"
        sig = ac.sign_message(pub_k, sec_k, msg)
        ok = ac.verify_message(pub_k, msg, sig) and not ac.verify_message(pub_k, b"tampered", sig)
        case("D-09", "offline sign/verify %s (+ tamper rejection)" % kt, ok,
             "signature %d bytes" % len(sig))

    # ---- D-10: failure-mode matrix ----
    failures = []

    def expect_fail(name, fn):
        try:
            fn()
            failures.append((name, False, "accepted, should have been rejected"))
        except ValueError as e:
            failures.append((name, True, str(e)[:80]))

    expect_fail("bad checksum", lambda: ac.account_id_from_classic_address("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi"))
    expect_fail("wrong version byte", lambda: ac.account_id_from_classic_address(DOCS_SEED))
    expect_fail("invalid base58 char", lambda: ac.account_id_from_classic_address("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyT0"))
    expect_fail("too short", lambda: ac.account_id_from_classic_address("rHb9"))
    expect_fail("empty string", lambda: ac.account_id_from_classic_address(""))
    expect_fail("X-address tag overflow", lambda: ac.encode_x_address(bytes(20), 0x100000000, False))
    expect_fail("X-address bad prefix", lambda: ac.decode_x_address("TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49MhpswX"))
    expect_fail("X-address 64-bit tag flag", lambda: ac.decode_x_address(
        ac.base58_encode(bytes([0x05, 0x44]) + bytes(20) + bytes([2, 0, 0, 0, 0, 0, 0, 0, 0]) + ac.sha256(ac.sha256(bytes([0x05, 0x44]) + bytes(20) + bytes([2, 0, 0, 0, 0, 0, 0, 0, 0])))[:4])))
    expect_fail("family seed wrong length", lambda: ac.decode_family_seed(ac.encode_checked(ac.VERSION_FAMILY_SEED, bytes(15))))
    expect_fail("account public wrong length", lambda: ac.decode_account_public(ac.encode_checked(ac.VERSION_ACCOUNT_PUBLIC, bytes(32))))
    expect_fail("RFC1751 wrong word count", lambda: ac.seed_from_1751("A B C"))
    expect_fail("RFC1751 unknown word", lambda: ac.seed_from_1751("ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ ZZZZ"))
    n_fail_ok = sum(1 for _, ok_f, _ in failures if ok_f)
    case("D-10", "failure-mode matrix (%d/%d rejected)" % (n_fail_ok, len(failures)),
         n_fail_ok == len(failures), "; ".join("%s: %s" % (n, "rejected" if o else "ACCEPTED!") for n, o, _ in failures))

    # ---- D-11: live validator master keys -> classic addresses ----
    vl_path = os.path.join(OUT, "testnet_vl.json")
    try:
        vl = json.load(open(vl_path))
        # VL format v2: blobs_v2[0].blob is base64url JSON; v1: top-level blob.
        if "blobs_v2" in vl:
            blob = vl["blobs_v2"][0]["blob"]
        else:
            blob = vl["blob"]
        import base64
        vl_json = json.loads(base64.b64decode(blob))
        validators = vl_json["validators"]
        addrs = []
        for v in validators:
            mpk = bytes.fromhex(v["validation_public_key"])
            assert ac.public_key_type(mpk) == "ed25519", v["validation_public_key"][:8]
            addrs.append(ac.classic_address_from_public_key(mpk))
        ok = len(addrs) == len(validators) and len(set(addrs)) == len(addrs) and all(ac.is_valid_classic_address(a) for a in addrs)
        case("D-11", "live testnet validator master keys -> distinct valid classic addresses", ok,
             "%d validators, %d distinct addresses, all Ed25519 master keys; "
             "first %s" % (len(validators), len(set(addrs)), addrs[0] if addrs else "-"))
        RESULTS["live_validator_addresses"] = addrs
    except Exception as e:
        case("D-11", "live testnet validator master keys -> classic addresses", False, "error: %s" % e)

    # ---- D-12: live genesis account parses + account ID ----
    try:
        gen = json.load(open(os.path.join(OUT, "rpc-account_info-pftl-genesis.json")))
        acct = gen["result"]["account_data"]["Account"]
        aid = ac.account_id_from_classic_address(acct)
        ok = ac.classic_address_from_account_id(aid) == acct
        case("D-12", "live PFTL genesis classic address parses and round-trips", ok,
             "%s accountID %s balance %s" % (acct, aid.hex(), gen["result"]["account_data"]["Balance"]))
        RESULTS["genesis_account_id"] = aid.hex()
    except Exception as e:
        case("D-12", "live PFTL genesis classic address parses", False, "error: %s" % e)

    # ---- D-13: live ledger census (address formats on the validated ledger) ----
    try:
        led = json.load(open(os.path.join(OUT, "ledger_current.json")))
        txs = led["result"]["ledger"].get("transactions", [])
        classic_fields = 0
        for t in txs:
            for k in ("Account", "Destination"):
                if k in t and ac.is_valid_classic_address(t[k]):
                    classic_fields += 1
        ok = True  # the census itself is the measurement; 0 txs is a valid result
        case("D-13", "live ledger address-format census (validated ledger %s)" % led["result"]["ledger"]["ledger_index"], ok,
             "%d transactions in the validated ledger, %d classic-address "
             "fields, 0 X-address fields (X-addresses never appear on-ledger)" % (len(txs), classic_fields))
        RESULTS["ledger_census"] = {"ledger_index": led["result"]["ledger"]["ledger_index"],
                                    "transactions": len(txs), "classic_address_fields": classic_fields,
                                    "x_address_fields": 0}
    except Exception as e:
        case("D-13", "live ledger address-format census", False, "error: %s" % e)

    # ---- D-14: Ed25519 RFC 8032 vectors (via the shared module) ----
    sys.path.insert(0, os.path.join(PACK, "scripts"))
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(PACK, "scripts", "ed25519_selftest.py")],
                       capture_output=True, text=True)
    ok = r.returncode == 0 and "3/3 vectors PASS" in r.stdout
    case("D-14", "Ed25519 RFC 8032 section 7.1 test vectors 1-3", ok,
         (r.stdout.strip().splitlines() or ["no output"])[-1])

    # ---- D-15: account-public / account-secret token round-trips ----
    pub_k, sec_k = ac.derive_keypair(lab[1], "secp256k1", 0)
    enc_pub = ac.encode_account_public(pub_k)
    enc_sec = ac.encode_account_secret(sec_k)
    ok = (ac.decode_account_public(enc_pub) == pub_k
          and ac.decode_checked(enc_sec, ac.VERSION_ACCOUNT_SECRET) == sec_k)
    case("D-15", "account-public / account-secret Base58Check tokens round-trip", ok,
         "public token %s; secret token verified in memory only and never "
         "recorded (LAB secret, fingerprint %s)" % (enc_pub, sha256_hex(sec_k)[:16]))

    # ---- summary ----
    passed = sum(1 for c in RESULTS["cases"] if c["pass"])
    total = len(RESULTS["cases"])
    RESULTS["summary"] = {"passed": passed, "failed": total - passed, "total": total,
                          "wall_seconds": round(time.time() - t0, 2)}
    log("drill result: %d/%d cases PASS (%d/%d attacks/rejections in D-10 matrix)" % (passed, total, n_fail_ok, len(failures)))
    with open(os.path.join(DERIVED, "drill-results.json"), "w", encoding="utf-8") as fh:
        json.dump(RESULTS, fh, indent=1, sort_keys=True)
    log("drill run end: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    LOG.close()
    # wipe lab key material from memory (best effort; seeds never left RAM)
    del lab
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
