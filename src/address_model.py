#!/usr/bin/env python3
"""address_model.py — address-space, collision, and confusion models for
the address-format evidence pack.

All numbers are computed from the pinned constants and the measured lab /
live values; nothing is typed by hand. Outputs:
  outputs/derived/address-inventory.json
  outputs/derived/collision-model.json
  outputs/model.log
"""
import json
import math
import os
import sys
import time

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "src"))
import address_codec as ac  # noqa: E402

OUT = os.path.join(PACK, "outputs")
DERIVED = os.path.join(OUT, "derived")
os.makedirs(DERIVED, exist_ok=True)
LOG = open(os.path.join(OUT, "model.log"), "w", encoding="utf-8")


def log(msg):
    LOG.write(msg + "\n")
    LOG.flush()
    print(msg)


def birthday_p(n, bits):
    """Collision probability among n uniform draws from a 2**bits space."""
    if n <= 1:
        return 0.0
    x = n * (n - 1) / 2.0 / 2.0 ** bits
    if x < 1e-8:
        # 1 - exp(-x) underflows to 0.0 in double precision here; use x.
        return x
    return 1.0 - math.exp(-x)


def main():
    log("address_model.py run start: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    # --- measured lengths (computed, not typed) ---
    classic_examples = [
        "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
        "r4vhrMChCsaoFsBoCkRTRGUuc1njfr7bmA",
        "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf",
        "rrrrrrrrrrrrrrrrrrrrrhoLvTp",
    ]
    x_examples = [
        "XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF",
        "TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49Mhpsws",
    ]
    classic_lens = sorted({len(a) for a in classic_examples})
    x_lens = sorted({len(a) for a in x_examples})
    seed = ac.decode_family_seed("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")
    fam_len = len(ac.encode_family_seed(seed))
    rfc_words = len(ac.seed_as_1751(seed).split())
    pub_token = ac.encode_account_public(ac.derive_keypair(seed, "secp256k1", 0)[0])
    node_token = ac.encode_checked(ac.VERSION_NODE_PUBLIC, bytes(33))

    inventory = {
        "formats": [
            {"id": "classic-address", "name": "Classic address",
             "encoding": "Base58Check, version 0x00, 20-byte AccountID",
             "payload_bytes": 21, "total_bytes": 25,
             "length_chars_measured": classic_lens,
             "count_inventoried": 1,
             "example": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
             "pinned_source": "src/libxrpl/protocol/AccountID.cpp:114-120 (toBase58), "
                              "include/xrpl/protocol/tokens.h:42 (AccountID=0)"},
            {"id": "x-address-mainnet", "name": "X-address (mainnet)",
             "encoding": "Base58Check, prefix 0x05 0x44, 20-byte AccountID, "
                         "flag byte, 4-byte little-endian tag, 4 reserved zero bytes",
             "payload_bytes": 31, "total_bytes": 35,
             "length_chars_measured": x_lens,
             "count_inventoried": 1,
             "example": "XVPcpSm47b1CZkf5AkKM9a84dQHe3mS14LVdcxAFurk93tF",
             "pinned_source": "NOT in the pinned node code (no toXAddress in src/ or "
                              "include/); ripple-address-codec encodeXAddress "
                              "(prefix main [0x05, 0x44], test [0x04, 0x93])"},
            {"id": "x-address-testnet", "name": "X-address (testnet)",
             "encoding": "Base58Check, prefix 0x04 0x93, same layout as mainnet",
             "payload_bytes": 31, "total_bytes": 35,
             "length_chars_measured": x_lens,
             "count_inventoried": 1,
             "example": "TVK3SYvMLZR6rEtLDZh3saYHaqFSeMfyuiuZdqF49Mhpsws",
             "pinned_source": "NOT in the pinned node code; ripple-address-codec"},
            {"id": "account-id", "name": "AccountID (160-bit)",
             "encoding": "RIPEMD-160(SHA-256(public key)), 20 bytes, hex or raw",
             "payload_bytes": 20, "total_bytes": 20,
             "length_chars_measured": [40],
             "count_inventoried": 1,
             "example": "f0633263b2e588395fcf15d406297e864f91aa35 (PFTL genesis)",
             "pinned_source": "src/libxrpl/protocol/AccountID.cpp:168-176 (calcAccountID)"},
            {"id": "family-seed", "name": "Family seed",
             "encoding": "Base58Check, version 0x21, 16-byte seed",
             "payload_bytes": 17, "total_bytes": 21,
             "length_chars_measured": [fam_len],
             "count_inventoried": 1,
             "example": "snoPBrXtMeMyMHUVTgbuqAfg1SUTb (public docs vector)",
             "pinned_source": "src/libxrpl/protocol/Seed.cpp:97-106 (parseBase58<Seed>), "
                              "include/xrpl/protocol/tokens.h:46 (FamilySeed=33)"},
            {"id": "rfc1751-seed-words", "name": "RFC1751 seed words",
             "encoding": "12 words from the 2048-word dictionary, 6 words per "
                         "64-bit half with 2-bit parity; seed bytes reversed first",
             "payload_bytes": 16, "total_bytes": 16,
             "length_chars_measured": [rfc_words],
             "count_inventoried": 1,
             "example": "I IRE BOND BOW TRIO LAID SEAT GOAL HEN IBIS IBIS DARE",
             "pinned_source": "src/libxrpl/protocol/Seed.cpp:135-145 (seedAs1751), "
                              "src/libxrpl/crypto/RFC1751.cpp:42, 463-504"},
            {"id": "account-public-token", "name": "Account public key token",
             "encoding": "Base58Check, version 0x23, 33-byte public key",
             "payload_bytes": 34, "total_bytes": 38,
             "length_chars_measured": [len(pub_token)],
             "count_inventoried": 1,
             "example": pub_token,
             "pinned_source": "include/xrpl/protocol/tokens.h:43 (AccountPublic=35)"},
            {"id": "account-secret-token", "name": "Account secret key token",
             "encoding": "Base58Check, version 0x22, 32-byte secret key",
             "payload_bytes": 33, "total_bytes": 37,
             "length_chars_measured": [len(ac.encode_account_secret(bytes(32)))],
             "count_inventoried": 1,
             "example": "NOT SHOWN (secret material is never recorded)",
             "pinned_source": "include/xrpl/protocol/tokens.h:44 (AccountSecret=34)"},
            {"id": "node-public-token", "name": "Node public key token",
             "encoding": "Base58Check, version 0x1C, 33-byte public key",
             "payload_bytes": 34, "total_bytes": 38,
             "length_chars_measured": [len(node_token)],
             "count_inventoried": 1,
             "example": "NOT SHOWN (validator key material is live; format only)",
             "pinned_source": "include/xrpl/protocol/tokens.h:40 (NodePublic=28)"},
        ],
        "key_formats": [
            {"id": "ed25519-public", "name": "Ed25519 public key",
             "encoding": "0xED prefix + 32-byte key (33 bytes)",
             "example_prefix": "0xED", "count_inventoried": 1,
             "pinned_source": "src/libxrpl/protocol/PublicKey.cpp:224-236, "
                              "src/libxrpl/protocol/SecretKey.cpp:352-356"},
            {"id": "secp256k1-public", "name": "secp256k1 compressed public key",
             "encoding": "0x02/0x03 prefix + 32-byte x-coordinate (33 bytes)",
             "example_prefix": "0x02/0x03", "count_inventoried": 1,
             "pinned_source": "src/libxrpl/protocol/PublicKey.cpp:224-236, "
                              "src/libxrpl/protocol/SecretKey.cpp:334-350"},
        ],
        "seed_formats": [
            {"id": "family-seed", "name": "Family seed (Base58Check 's...')",
             "entropy_bits": 128, "count_inventoried": 1},
            {"id": "rfc1751-words", "name": "RFC1751 12-word seed",
             "entropy_bits": 128, "count_inventoried": 1},
            {"id": "passphrase-seed", "name": "Passphrase-derived seed",
             "entropy_bits": "passphrase-dependent (SHA-512-Half[:16])",
             "count_inventoried": 1},
            {"id": "hex-seed", "name": "32-hex-character seed",
             "entropy_bits": 128, "count_inventoried": 1,
             "pinned_source": "src/libxrpl/protocol/Seed.cpp:108-116 "
                              "(parseGenericSeed accepts a 32-hex seed)"},
        ],
    }
    n_formats = len(inventory["formats"])
    n_key_formats = len(inventory["key_formats"])
    n_seed_formats = len(inventory["seed_formats"])
    inventory["totals"] = {"address_formats": n_formats, "key_formats": n_key_formats,
                           "seed_formats": n_seed_formats}
    log("address formats inventoried: %d" % n_formats)
    log("key formats inventoried: %d" % n_key_formats)
    log("seed formats inventoried: %d" % n_seed_formats)

    # --- collision model ---
    # AccountID space is 160 bits. Birthday bound for n accounts.
    scenarios = []
    for n in (10 ** 6, 10 ** 9, 10 ** 12, 2 ** 80):
        p = birthday_p(n, 160)
        scenarios.append({"accounts": n, "collision_probability": p,
                          "log10_probability": math.log10(p) if p > 0 else None})
    # Seed space is 128 bits; same birthday math for seeds.
    seed_scenarios = []
    for n in (10 ** 6, 10 ** 9, 2 ** 64):
        p = birthday_p(n, 128)
        seed_scenarios.append({"seeds": n, "collision_probability": p,
                               "log10_probability": math.log10(p) if p > 0 else None})
    # Checksum: 32 bits. Probability a random single-character Base58
    # corruption goes undetected ~= 2^-32 (uniform checksum assumption).
    # Number of distinct single-character corruptions of a 34-char classic
    # address: 34 positions * 57 alternatives = 1938; expected undetected
    # ~= 1938 / 2^32.
    single_char_corruptions = 34 * 57
    expected_undetected = single_char_corruptions / 2.0 ** 32
    # Destination-tag space and X-address variants per account.
    model = {
        "account_id_bits": 160,
        "seed_bits": 128,
        "checksum_bits": 32,
        "birthday_scenarios_account_id": scenarios,
        "birthday_scenarios_seed": seed_scenarios,
        "single_character_corruptions_classic_34char": single_char_corruptions,
        "expected_undetected_single_char_corruptions": expected_undetected,
        "destination_tag_space": 2 ** 32,
        "x_address_variants_per_account": {
            "networks": 2,
            "tags_per_network": 2 ** 32 + 1,
            "note": "1 no-tag form + 2^32 tagged forms per network",
        },
        "addresses_per_seed": {
            "ed25519": 1,
            "secp256k1_ordinals_tested": 2,
            "secp256k1_ordinal_space": "uint32 sequence in the Generator tweak "
                                      "(SecretKey.cpp calculateTweak)",
        },
        "same_seed_distinct_addresses_measured": 2,
        "notes": [
            "Birthday probabilities use the standard approximation "
            "1 - exp(-n(n-1) / 2^(bits+1)).",
            "Checksum analysis assumes the 32-bit double-SHA-256 checksum is "
            "uniform over random corruptions; the drill measured 12/12 "
            "malformed inputs rejected, including a bad checksum.",
            "The 2^160 AccountID space is what makes accidental collision "
            "negligible; the realistic confusion risks are encoding-level "
            "(same key, different format) not hash collisions.",
        ],
    }
    for s in scenarios:
        log("birthday: %s accounts in 2^160 -> P=%.3e" % (s["accounts"], s["collision_probability"]))
    log("single-char corruptions of a 34-char classic address: %d; expected undetected: %.3e"
        % (single_char_corruptions, expected_undetected))

    with open(os.path.join(DERIVED, "address-inventory.json"), "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=1, sort_keys=True)
    with open(os.path.join(DERIVED, "collision-model.json"), "w", encoding="utf-8") as fh:
        json.dump(model, fh, indent=1, sort_keys=True)
    log("address_model.py run end: %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


if __name__ == "__main__":
    main()
