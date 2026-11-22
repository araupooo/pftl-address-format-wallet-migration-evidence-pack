#!/usr/bin/env python3
"""address_codec.py — pure-Python reference implementation of the PFTL/XRPL
address, seed, and key-derivation formats, built from the pinned postfiatd
source (commit 0085a1ff885d6a446369cf73a4430f75af22be55).

Standard library only. No live key material: every key used by callers is
freshly generated LAB test material.

Pinned-source mapping (all line numbers verified with grep -n on a local
checkout of the pinned commit):
  TokenType enum (FamilySeed=33, AccountID=0, AccountPublic=35,
    AccountSecret=34, NodePublic=28, NodePrivate=32):
      include/xrpl/protocol/tokens.h:38-46
  XRPL Base58 alphabet:
      src/libxrpl/protocol/tokens.cpp:143
  Base58Check checksum (first 4 bytes of double-SHA-256) and the
  <type><token><checksum> layout:
      src/libxrpl/protocol/tokens.cpp:174-194, 327-342, 659
  Seed (16 bytes), randomSeed (CSPRNG), generateSeed (SHA-512-Half of the
  passphrase, first 16 bytes), parseBase58<Seed> (FamilySeed token):
      src/libxrpl/protocol/Seed.cpp:66-94, 97-131
  seedAs1751 (reverse the 16 seed bytes, then RFC1751-encode):
      src/libxrpl/protocol/Seed.cpp:135-145
  RFC1751 dictionary (2048 words), btoe/etob, parity, standard():
      src/libxrpl/crypto/RFC1751.cpp:42, 301-330, 365-460, 463-504
  secp256k1 root-key derivation (SHA-512-Half(seed || seq_be32), seq 0..127)
  and the Generator tweak (SHA-512-Half(generator || seq || subseq)):
      src/libxrpl/protocol/SecretKey.cpp:86-118, 145-175, 180-223
  Ed25519 secret (SHA-512-Half(seed)), public key (0xED prefix):
      src/libxrpl/protocol/SecretKey.cpp:309-327, 330-356
  KeyType enum (secp256k1=0, ed25519=1):
      include/xrpl/protocol/KeyType.h:28-31
  Public-key type detection (0xED -> ed25519, 0x02/0x03 -> secp256k1):
      src/libxrpl/protocol/PublicKey.cpp:224-236
  AccountID = RIPEMD-160(SHA-256(public key)):
      src/libxrpl/protocol/AccountID.cpp:168-176
  Classic address = Base58Check(AccountID token, 20-byte AccountID):
      src/libxrpl/protocol/AccountID.cpp:114-120
  Signing: Ed25519 signs the message directly; secp256k1 signs
  SHA-512-Half(message) with ECDSA (RFC 6979 nonce, DER encoding):
      src/libxrpl/protocol/SecretKey.cpp:232-307

X-addresses are NOT in the pinned node code at all (no toXAddress anywhere
in src/ or include/): the format is specified by the client-side
ripple-address-codec library (XRPLF), whose encode/decode logic this module
reproduces exactly (prefix main [0x05, 0x44], test [0x04, 0x93]; layout
prefix(2) || accountID(20) || flag(1) || tag(4, little-endian) ||
reserved(4 zero bytes); Base58Check over the 31 bytes).
"""
import hashlib
import hmac
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import ed25519 as _ed25519  # noqa: E402  (pure-Python RFC 8032, validated)

# ------------------------------------------------------------------ hashes
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sha512_half(data: bytes) -> bytes:
    """First 32 bytes of SHA-512 — rippled's sha512Half."""
    return hashlib.sha512(data).digest()[:32]


def ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


# ------------------------------------------------------------------ base58
ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_ALPHABET_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def base58_encode(data: bytes) -> str:
    """Base58 with the XRPL alphabet. Leading zero bytes become 'r'."""
    n = int.from_bytes(data, "big") if data else 0
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    leading = 0
    for b in data:
        if b == 0:
            leading += 1
        else:
            break
    return "r" * leading + out


def base58_decode(s: str) -> bytes:
    """Inverse of base58_encode. Raises ValueError on a bad character."""
    n = 0
    for c in s:
        if c not in _ALPHABET_INDEX:
            raise ValueError("invalid base58 character: %r" % c)
        n = n * 58 + _ALPHABET_INDEX[c]
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    leading = 0
    for c in s:
        if c == "r":
            leading += 1
        else:
            break
    return b"\x00" * leading + raw


def encode_checked(version: bytes, payload: bytes) -> str:
    """Base58Check: version || payload || first-4-bytes(double-SHA-256)."""
    body = version + payload
    return base58_encode(body + sha256(sha256(body))[:4])


def decode_checked(s: str, expected_version: bytes) -> bytes:
    """Decode a Base58Check token, verifying checksum and version byte(s)."""
    raw = base58_decode(s)
    if len(raw) < len(expected_version) + 4:
        raise ValueError("token too short")
    version, payload, checksum = (
        raw[: len(expected_version)],
        raw[len(expected_version): -4],
        raw[-4:],
    )
    if version != expected_version:
        raise ValueError(
            "version mismatch: got %s, expected %s"
            % (version.hex(), expected_version.hex())
        )
    if sha256(sha256(raw[:-4]))[:4] != checksum:
        raise ValueError("checksum_invalid")
    return payload


# ------------------------------------------------------- token type bytes
VERSION_ACCOUNT_ID = b"\x00"       # TokenType::AccountID = 0
VERSION_FAMILY_SEED = b"\x21"      # TokenType::FamilySeed = 33
VERSION_ACCOUNT_PUBLIC = b"\x23"   # TokenType::AccountPublic = 35
VERSION_ACCOUNT_SECRET = b"\x22"   # TokenType::AccountSecret = 34
VERSION_NODE_PUBLIC = b"\x1c"      # TokenType::NodePublic = 28
VERSION_NODE_PRIVATE = b"\x20"     # TokenType::NodePrivate = 32

X_PREFIX_MAIN = bytes([0x05, 0x44])
X_PREFIX_TEST = bytes([0x04, 0x93])

# ------------------------------------------------------- classic addresses
def classic_address_from_account_id(account_id: bytes) -> str:
    if len(account_id) != 20:
        raise ValueError("AccountID must be 20 bytes")
    return encode_checked(VERSION_ACCOUNT_ID, account_id)


def account_id_from_classic_address(address: str) -> bytes:
    payload = decode_checked(address, VERSION_ACCOUNT_ID)
    if len(payload) != 20:
        raise ValueError("AccountID must be 20 bytes, got %d" % len(payload))
    return payload


def is_valid_classic_address(address: str) -> bool:
    try:
        account_id_from_classic_address(address)
        return True
    except ValueError:
        return False


# ------------------------------------------------------- X-addresses
def encode_x_address(account_id: bytes, tag=None, test: bool = False) -> str:
    """Encode a classic address as an X-address.

    tag is None/False for "no tag"; otherwise a 32-bit unsigned integer.
    Layout (ripple-address-codec): prefix(2) || accountID(20) || flag(1)
    || tag(4, little-endian) || reserved(4 zero bytes); Base58Check.
    """
    if len(account_id) != 20:
        raise ValueError("Account ID must be 20 bytes")
    if tag is not None and tag is not False and tag > 0xFFFFFFFF:
        raise ValueError("Invalid tag")
    flag = 0 if (tag is None or tag is False) else 1
    the_tag = 0 if (tag is None or tag is False) else tag
    body = (X_PREFIX_TEST if test else X_PREFIX_MAIN) + account_id + bytes([
        flag,
        the_tag & 0xFF,
        (the_tag >> 8) & 0xFF,
        (the_tag >> 16) & 0xFF,
        (the_tag >> 24) & 0xFF,
        0, 0, 0, 0,
    ])
    return base58_encode(body + sha256(sha256(body))[:4])


def decode_x_address(x_address: str):
    """Return (account_id, tag, test). tag is False when no tag is present."""
    raw = base58_decode(x_address)
    if len(raw) != 31 + 4:
        raise ValueError("X-address must decode to 35 bytes, got %d" % len(raw))
    body, checksum = raw[:-4], raw[-4:]
    if sha256(sha256(body))[:4] != checksum:
        raise ValueError("checksum_invalid")
    prefix = body[:2]
    if prefix == X_PREFIX_MAIN:
        test = False
    elif prefix == X_PREFIX_TEST:
        test = True
    else:
        raise ValueError("Invalid X-address: bad prefix")
    account_id = body[2:22]
    flag = body[22]
    if flag >= 2:
        raise ValueError("Unsupported X-address")
    if flag == 1:
        tag = body[23] + body[24] * 0x100 + body[25] * 0x10000 + body[26] * 0x1000000
    else:
        if body[23:31] != b"\x00" * 8:
            raise ValueError("remaining bytes must be zero")
        tag = False
    return account_id, tag, test


def classic_address_to_x_address(classic_address: str, tag=None, test: bool = False) -> str:
    return encode_x_address(account_id_from_classic_address(classic_address), tag, test)


def x_address_to_classic_address(x_address: str):
    account_id, tag, test = decode_x_address(x_address)
    return classic_address_from_account_id(account_id), tag, test


# ------------------------------------------------------- seeds
def encode_family_seed(seed16: bytes) -> str:
    if len(seed16) != 16:
        raise ValueError("Seed must be 16 bytes")
    return encode_checked(VERSION_FAMILY_SEED, seed16)


def decode_family_seed(s: str) -> bytes:
    payload = decode_checked(s, VERSION_FAMILY_SEED)
    if len(payload) != 16:
        raise ValueError("Seed must be 16 bytes, got %d" % len(payload))
    return payload


def generate_seed_from_passphrase(passphrase: str) -> bytes:
    """generateSeed: first 16 bytes of SHA-512-Half of the passphrase."""
    return sha512_half(passphrase.encode("utf-8"))[:16]


def random_seed_bytes() -> bytes:
    """randomSeed: 16 bytes from the OS CSPRNG (lab keys only)."""
    return os.urandom(16)


# ------------------------------------------------------- RFC1751
_WORDS = None


def _load_words():
    global _WORDS
    if _WORDS is None:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "fixtures", "rfc1751-words.csv")
        words = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("index"):
                    continue
                idx, word = line.split(",", 1)
                words.append((int(idx), word.strip()))
        words.sort()
        _WORDS = [w for _, w in words]
        if len(_WORDS) != 2048:
            raise ValueError("RFC1751 dictionary must have 2048 words, got %d" % len(_WORDS))
    return _WORDS


def _extract(buf: bytes, start: int, length: int) -> int:
    """RFC1751::extract — big-endian bit extraction (RFC1751.cpp ~278-295)."""
    shift_r = 24 - (length + (start % 8))
    cl = buf[start // 8]
    cc = buf[start // 8 + 1] if shift_r < 16 else 0
    cr = buf[start // 8 + 2] if shift_r < 8 else 0
    x = ((cl << 8 | cc) << 8 | cr)
    x = x >> shift_r
    x = x & (0xFFFF >> (16 - length))
    return x


def _insert(buf: bytearray, x: int, start: int, length: int) -> None:
    """RFC1751::insert — big-endian bit insertion."""
    shift = ((8 - ((start + length) % 8)) % 8)
    y = x << shift
    cl = (y >> 16) & 0xFF
    cc = (y >> 8) & 0xFF
    cr = y & 0xFF
    if shift + length > 16:
        buf[start // 8] |= cl
        buf[start // 8 + 1] |= cc
        buf[start // 8 + 2] |= cr
    elif shift + length > 8:
        buf[start // 8] |= cc
        buf[start // 8 + 1] |= cr
    else:
        buf[start // 8] |= cr


def _btoe(data8: bytes) -> str:
    """RFC1751::btoe — 8 bytes -> 6 words (with 2-bit parity)."""
    words = _load_words()
    buf = bytearray(data8) + b"\x00"
    p = 0
    for i in range(0, 64, 2):
        p += _extract(bytes(buf), i, 2)
    buf[8] = (p & 3) << 6  # C++: char(p) << 6, truncated to a byte: low 2 bits of p
    return " ".join(words[_extract(bytes(buf), off, 11)] for off in (0, 11, 22, 33, 44, 55))


def _etob(words6):
    """RFC1751::etob — 6 words -> 8 bytes. Returns (rc, bytes).
    rc: 1 ok, 0 word not in dictionary, -1 badly formed, -2 parity wrong."""
    words = _load_words()
    index = {w: i for i, w in enumerate(words)}
    if len(words6) != 6:
        return -1, b""
    buf = bytearray(9)
    p = 0
    for raw_word in words6:
        word = raw_word.strip().upper().replace("1", "L").replace("0", "O").replace("5", "S")
        if len(word) < 1 or len(word) > 4:
            return -1, b""
        if word not in index:
            return 0, b""
        _insert(buf, index[word], p, 11)
        p += 11
    parity = 0
    for i in range(0, 64, 2):
        parity += _extract(bytes(buf), i, 2)
    if (parity & 3) != _extract(bytes(buf), 64, 2):
        return -2, b""
    return 1, bytes(buf[:8])


def seed_as_1751(seed16: bytes) -> str:
    """seedAs1751: reverse the 16 seed bytes, encode as 12 words."""
    if len(seed16) != 16:
        raise ValueError("Seed must be 16 bytes")
    rev = seed16[::-1]
    return _btoe(rev[:8]) + " " + _btoe(rev[8:])


def seed_from_1751(words12: str) -> bytes:
    """parseGenericSeed (rfc1751): 12 words -> 16 seed bytes (reversed)."""
    parts = words12.split()
    if len(parts) != 12:
        raise ValueError("RFC1751 seed must be 12 words, got %d" % len(parts))
    rc1, first = _etob(parts[:6])
    rc2, second = _etob(parts[6:])
    if rc1 != 1 or rc2 != 1:
        raise ValueError("RFC1751 decode failed: rc=%d,%d" % (rc1, rc2))
    return (first + second)[::-1]


# ------------------------------------------------------- secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _ec_mul(k: int, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def secp256k1_public_key(secret32: bytes) -> bytes:
    """Compressed public key (0x02/0x03 prefix + 32-byte x)."""
    d = int.from_bytes(secret32, "big")
    if not 1 <= d < N:
        raise ValueError("invalid secp256k1 secret")
    x, y = _ec_mul(d)
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")


def _derive_deterministic_root_key(seed16: bytes) -> bytes:
    """SecretKey.cpp deriveDeterministicRootKey: SHA-512-Half(seed||seq)."""
    for seq in range(128):
        candidate = sha512_half(seed16 + seq.to_bytes(4, "big"))
        d = int.from_bytes(candidate, "big")
        if 1 <= d < N:
            return candidate
    raise ValueError("Unable to derive generator from seed")


def _generator(seed16: bytes):
    root = _derive_deterministic_root_key(seed16)
    return root, secp256k1_public_key(root)


def _calculate_tweak(generator_pub33: bytes, ordinal: int) -> bytes:
    """SecretKey.cpp Generator::calculateTweak."""
    for subseq in range(128):
        candidate = sha512_half(
            generator_pub33 + ordinal.to_bytes(4, "big") + subseq.to_bytes(4, "big")
        )
        d = int.from_bytes(candidate, "big")
        if 1 <= d < N:
            return candidate
    raise ValueError("Unable to derive generator tweak")


def derive_keypair_secp256k1(seed16: bytes, ordinal: int = 0):
    """generateKeyPair(secp256k1, seed): Generator(seed)(ordinal)."""
    root, generator_pub = _generator(seed16)
    tweak = _calculate_tweak(generator_pub, ordinal)
    secret = (int.from_bytes(root, "big") + int.from_bytes(tweak, "big")) % N
    secret32 = secret.to_bytes(32, "big")
    return secp256k1_public_key(secret32), secret32


# ------------------------------------------------------- Ed25519
def derive_keypair_ed25519(seed16: bytes):
    """generateKeyPair(ed25519, seed): secret = SHA-512-Half(seed)."""
    secret32 = sha512_half(seed16)
    public32 = _ed25519.public_key(secret32)
    return b"\xed" + public32, secret32


def derive_keypair(seed16: bytes, key_type: str, ordinal: int = 0):
    if key_type == "ed25519":
        if ordinal != 0:
            raise ValueError("Ed25519 derivation has no ordinal family")
        return derive_keypair_ed25519(seed16)
    if key_type == "secp256k1":
        return derive_keypair_secp256k1(seed16, ordinal)
    raise ValueError("unknown key type: %s" % key_type)


# ------------------------------------------------------- account IDs
def public_key_type(pubkey: bytes):
    """PublicKey.cpp publicKeyType."""
    if len(pubkey) == 33:
        if pubkey[0] == 0xED:
            return "ed25519"
        if pubkey[0] in (0x02, 0x03):
            return "secp256k1"
    return None


def account_id_from_public_key(pubkey: bytes) -> bytes:
    """calcAccountID: RIPEMD-160(SHA-256(public key))."""
    return ripemd160(sha256(pubkey))


def classic_address_from_public_key(pubkey: bytes) -> str:
    return classic_address_from_account_id(account_id_from_public_key(pubkey))


def encode_account_public(pubkey: bytes) -> str:
    return encode_checked(VERSION_ACCOUNT_PUBLIC, pubkey)


def decode_account_public(s: str) -> bytes:
    payload = decode_checked(s, VERSION_ACCOUNT_PUBLIC)
    if len(payload) != 33 or public_key_type(payload) is None:
        raise ValueError("not a valid account public key")
    return payload


def encode_account_secret(secret32: bytes) -> str:
    return encode_checked(VERSION_ACCOUNT_SECRET, secret32)


# ------------------------------------------------------- signing (offline)
def _rfc6979_nonce(secret32: bytes, msg_hash32: bytes) -> int:
    """RFC 6979 deterministic nonce for secp256k1 (HMAC-SHA-256)."""
    x = secret32
    h1 = msg_hash32
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _der_encode(r: int, s: int) -> bytes:
    def _int_bytes(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b
    rb, sb = _int_bytes(r), _int_bytes(s)
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    return b"\x30" + bytes([len(body)]) + body


def _der_decode(sig: bytes):
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("not DER")
    if sig[1] != len(sig) - 2:
        raise ValueError("bad DER length")
    if sig[2] != 0x02:
        raise ValueError("bad DER r tag")
    rlen = sig[3]
    r = int.from_bytes(sig[4: 4 + rlen], "big")
    pos = 4 + rlen
    if sig[pos] != 0x02:
        raise ValueError("bad DER s tag")
    slen = sig[pos + 1]
    s = int.from_bytes(sig[pos + 2: pos + 2 + slen], "big")
    if pos + 2 + slen != len(sig):
        raise ValueError("trailing DER bytes")
    return r, s


def sign_message(pubkey: bytes, secret32: bytes, message: bytes) -> bytes:
    """SecretKey.cpp sign(): Ed25519 signs the message; secp256k1 signs
    SHA-512-Half(message) with ECDSA (DER, low-S canonical)."""
    key_type = public_key_type(pubkey)
    if key_type == "ed25519":
        # ed25519_sign(message, secret, public-without-prefix, sig-out)
        sig = _ed25519.sign(message, secret32, pubkey[1:])
        return sig
    if key_type == "secp256k1":
        digest = sha512_half(message)
        z = int.from_bytes(digest, "big")
        d = int.from_bytes(secret32, "big")
        k = _rfc6979_nonce(secret32, digest)
        r = _ec_mul(k)[0] % N
        if r == 0:
            raise ValueError("r == 0")
        s = (pow(k, N - 2, N) * (z + r * d)) % N
        if s == 0:
            raise ValueError("s == 0")
        if s > N // 2:  # fully canonical: low-S
            s = N - s
        return _der_encode(r, s)
    raise ValueError("unknown public key type")


def verify_message(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature produced by sign_message()."""
    key_type = public_key_type(pubkey)
    if key_type == "ed25519":
        try:
            return _ed25519.verify(signature, message, pubkey[1:])
        except Exception:
            return False
    if key_type == "secp256k1":
        try:
            r, s = _der_decode(signature)
        except ValueError:
            return False
        if not (1 <= r < N and 1 <= s < N):
            return False
        if s > N // 2:  # not fully canonical
            return False
        z = int.from_bytes(sha512_half(message), "big")
        w = pow(s, N - 2, N)
        u1 = (z * w) % N
        u2 = (r * w) % N
        point = _ec_add(_ec_mul(u1), _ec_mul(u2, _ec_point_from_compressed(pubkey)))
        if point is None:
            return False
        return point[0] % N == r
    return False


def _ec_point_from_compressed(pubkey: bytes):
    if pubkey[0] not in (0x02, 0x03):
        raise ValueError("not a compressed secp256k1 key")
    x = int.from_bytes(pubkey[1:], "big")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if (y & 1) != (pubkey[0] & 1):
        y = P - y
    return (x, y)


# ------------------------------------------------------- XRPL signing hash
SIGNING_HASH_PREFIX = b"STX\x00"  # 0x53545800


def signing_hash(serialized_tx: bytes) -> bytes:
    """The hash a transaction is signed over: SHA-512-Half(STX\0 || tx)."""
    return sha512_half(SIGNING_HASH_PREFIX + serialized_tx)
