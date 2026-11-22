#!/usr/bin/env python3
"""crosscheck.py — cross-implementation verification against xrpl-py 5.2.0
and ripple-keypairs / ripple-address-codec (npm).

Generates FRESH lab seeds in-process, passes them to a Node helper through
a 0600 temp file in /tmp (deleted immediately after the run), and compares
key derivation, classic/X-address encoding, and offline transaction
signatures across THREE independent implementations:
  1. this pack's reference implementation (src/address_codec.py)
  2. xrpl-py 5.2.0 (Python, pip)
  3. ripple-keypairs + ripple-address-codec (JavaScript, npm)

Nothing is submitted to any network. The offline test transaction is signed
only; the signed blob is never broadcast. Lab seeds are NEVER written into
the pack outputs — only derived public material (public keys, addresses,
signatures, timings) is recorded.

Usage: /tmp/a2a-venv/bin/python scripts/crosscheck.py
  (requires the xrpl-py venv at /tmp/a2a-venv and the npm packages in
  /tmp/a2a-npm; exits 2 if either is unavailable, so a clean-reproduce run
  can treat the cross-check as optional extended evidence.)

Outputs:
  outputs/crosscheck-results.json
  outputs/crosscheck-run.log
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "src"))
import address_codec as ac  # noqa: E402

OUT = os.path.join(PACK, "outputs")
os.makedirs(OUT, exist_ok=True)
LOG_PATH = os.path.join(OUT, "crosscheck-run.log")
LOG = open(LOG_PATH, "w", encoding="utf-8")
RESULTS = {"checks": [], "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def log(msg):
    LOG.write(msg + "\n")
    LOG.flush()
    print(msg)


def check(cid, title, ok, detail):
    RESULTS["checks"].append({"id": cid, "title": title, "pass": bool(ok), "detail": detail})
    log("%s %s: %s — %s" % ("PASS" if ok else "FAIL", cid, title, detail))
    return bool(ok)


VENV_PY = "/tmp/a2a-venv/bin/python"
NPM_DIR = "/tmp/a2a-npm"

NODE_HELPER = r"""
const fs = require('fs');
const k = require('ripple-keypairs');
const c = require('ripple-address-codec');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const out = { wallets: [], signatures: {} };
for (const seed of input.seeds) {
  const w = {};
  for (const algo of ['ecdsa-secp256k1', 'ed25519']) {
    const kp = k.deriveKeypair(seed, { algorithm: algo });
    const addr = k.deriveAddress(kp.publicKey);
    w[algo] = {
      publicKey: kp.publicKey,
      classicAddress: addr,
      xMainTag0: c.classicAddressToXAddress(addr, 0, false),
      xTestTag12345: c.classicAddressToXAddress(addr, 12345, true),
      xMainNoTag: c.classicAddressToXAddress(addr, false, false),
    };
  }
  out.wallets.push(w);
}
for (const [name, hex] of Object.entries(input.signMessages)) {
  out.signatures[name] = {};
  for (const seed of input.seeds) {
    const sec = k.deriveKeypair(seed);
    const ed = k.deriveKeypair(seed, { algorithm: 'ed25519' });
    out.signatures[name][seed.slice(0, 6) + '...'] = {
      secp256k1: k.sign(hex, sec.privateKey),
      ed25519: k.sign(hex, ed.privateKey),
    };
  }
}
console.log(JSON.stringify(out));
"""


def main():
    t0 = time.time()
    log("crosscheck run start: %s" % RESULTS["generated_at_utc"])
    # availability gate
    try:
        import xrpl  # noqa: F401
        from xrpl.wallet import Wallet  # noqa: F401
    except ImportError:
        log("xrpl-py not available in this interpreter; run with /tmp/a2a-venv/bin/python")
        return 2
    if not os.path.isdir(NPM_DIR) or not os.path.exists(os.path.join(NPM_DIR, "node_modules", "ripple-keypairs")):
        log("ripple-keypairs not installed under /tmp/a2a-npm; cross-check skipped")
        return 2

    from xrpl.wallet import Wallet
    from xrpl.models.transactions import Payment
    from xrpl.utils import xrp_to_drops
    from xrpl.core.binarycodec import encode_for_signing
    from xrpl.core.addresscodec import classic_address_to_xaddress

    # --- fresh LAB seeds (in-process only; never written to the pack) ---
    lab_seeds = [ac.encode_family_seed(ac.random_seed_bytes()) for _ in range(3)]
    seeds = ["snoPBrXtMeMyMHUVTgbuqAfg1SUTb"] + lab_seeds  # docs vector + 3 lab
    log("cross-checking %d seeds (1 public docs vector + 3 fresh LAB seeds)" % len(seeds))

    # --- offline test transaction (signed, never submitted) ---
    # One Payment per seed/algorithm, built offline with fixed fields.
    sign_messages = {}
    tx_records = []
    for i, seed in enumerate(seeds):
        for algo in ("secp256k1", "ed25519"):
            w = Wallet.from_seed(seed, algorithm=algo)
            tx = Payment(account=w.classic_address, amount=xrp_to_drops(1),
                         destination="r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
                         fee="12", sequence=1, last_ledger_sequence=9000000)
            txdict = tx.to_xrpl()
            txdict["SigningPubKey"] = w.public_key
            sb = encode_for_signing(txdict)
            if isinstance(sb, str):
                sb = bytes.fromhex(sb)
            key = "tx-%d-%s" % (i, algo)
            sign_messages[key] = sb.hex()
            tx_records.append({"key": key, "seed_index": i, "algorithm": algo,
                               "account": w.classic_address,
                               "signing_bytes_sha256": hashlib.sha256(sb).hexdigest(),
                               "signing_hash": hashlib.sha512(sb).digest()[:32].hex()})
    RESULTS["test_transactions"] = tx_records

    # --- Node helper run (seeds via a 0600 temp file, deleted afterwards) ---
    node_input = {"seeds": seeds, "signMessages": sign_messages}
    fd, tmp_in = tempfile.mkstemp(prefix="a2a-crosscheck-", suffix=".json", dir="/tmp")
    os.chmod(tmp_in, 0o600)
    helper_path = None
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(node_input, fh)
        fd2, helper_path = tempfile.mkstemp(prefix="a2a-helper-", suffix=".js", dir=NPM_DIR)
        with os.fdopen(fd2, "w") as fh:
            fh.write(NODE_HELPER)
        r = subprocess.run(["node", helper_path, tmp_in], cwd=NPM_DIR,
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            log("node helper failed: %s" % r.stderr[-500:])
            return 1
        js = json.loads(r.stdout)
    finally:
        os.unlink(tmp_in)
        if helper_path and os.path.exists(helper_path):
            os.unlink(helper_path)
        log("temp seed file deleted (seeds never persisted)")

    # --- compare: derivation + addresses across 3 implementations ---
    for i, seed in enumerate(seeds):
        label = "docs" if i == 0 else "lab-%d" % i
        seed16 = ac.decode_family_seed(seed)
        for algo, js_algo in (("secp256k1", "ecdsa-secp256k1"), ("ed25519", "ed25519")):
            ref_pub, _ = ac.derive_keypair(seed16, algo)
            ref_addr = ac.classic_address_from_public_key(ref_pub)
            js_w = js["wallets"][i][js_algo]
            py_w = Wallet.from_seed(seed, algorithm=algo)
            ok_pub = ref_pub.hex().upper() == js_w["publicKey"] and ref_pub.hex().upper() == py_w.public_key.upper()
            ok_addr = ref_addr == js_w["classicAddress"] == py_w.classic_address
            check("X-%s-%s-derive" % (label, algo),
                  "3-way derivation agreement (%s, %s)" % (label, algo), ok_pub and ok_addr,
                  "ref %s | js %s | py %s" % (ref_addr, js_w["classicAddress"], py_w.classic_address))
            # X-addresses: reference vs JS codec vs xrpl-py
            ref_x_main = ac.classic_address_to_x_address(ref_addr, 0, False)
            ref_x_test = ac.classic_address_to_x_address(ref_addr, 12345, True)
            ref_x_notag = ac.classic_address_to_x_address(ref_addr, None, False)
            py_x_main = classic_address_to_xaddress(ref_addr, 0, False)
            py_x_test = classic_address_to_xaddress(ref_addr, 12345, True)
            ok_x = (ref_x_main == js_w["xMainTag0"] == py_x_main
                    and ref_x_test == js_w["xTestTag12345"] == py_x_test
                    and ref_x_notag == js_w["xMainNoTag"])
            check("X-%s-%s-xaddr" % (label, algo),
                  "3-way X-address agreement (%s, %s)" % (label, algo), ok_x,
                  "main-tag0 %s test-tag12345 %s no-tag %s" % (ref_x_main, ref_x_test, ref_x_notag))

    # --- compare: offline signatures, byte-for-byte, all three ---
    for rec in tx_records:
        key, i, algo = rec["key"], rec["seed_index"], rec["algorithm"]
        seed16 = ac.decode_family_seed(seeds[i])
        ref_pub, ref_sec = ac.derive_keypair(seed16, algo)
        sb = bytes.fromhex(sign_messages[key])
        my_sig = ac.sign_message(ref_pub, ref_sec, sb)
        # xrpl-py signature (sign offline; never submitted)
        w = Wallet.from_seed(seeds[i], algorithm=algo)
        tx = Payment(account=w.classic_address, amount=xrp_to_drops(1),
                     destination="r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
                     fee="12", sequence=1, last_ledger_sequence=9000000)
        signed = xrpl.transaction.sign(tx, w)
        py_sig = bytes.fromhex(signed.txn_signature)
        js_sig = bytes.fromhex(js["signatures"][key][seeds[i][:6] + "..."][algo])
        ok = (my_sig == py_sig == js_sig)
        ok_verify = ac.verify_message(ref_pub, sb, py_sig) and ac.verify_message(ref_pub, sb, js_sig)
        check("X-%s-sig" % key, "3-way offline signature agreement (%s)" % key, ok and ok_verify,
              "sig %d bytes, identical across ref/xrpl-py/ripple-keypairs: %s; "
              "reference verify of both foreign signatures: %s" % (len(my_sig), ok, ok_verify))
        rec["signature_hex"] = my_sig.hex()
        rec["signature_bytes"] = len(my_sig)

    passed = sum(1 for c in RESULTS["checks"] if c["pass"])
    total = len(RESULTS["checks"])
    RESULTS["summary"] = {"passed": passed, "failed": total - passed, "total": total,
                          "wall_seconds": round(time.time() - t0, 2),
                          "implementations": ["reference (this pack, pure Python stdlib)",
                                              "xrpl-py 5.2.0", "ripple-keypairs + ripple-address-codec (npm)"]}
    log("crosscheck result: %d/%d checks PASS" % (passed, total))
    with open(os.path.join(OUT, "crosscheck-results.json"), "w", encoding="utf-8") as fh:
        json.dump(RESULTS, fh, indent=1, sort_keys=True)
    log("crosscheck run end: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    LOG.close()
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
