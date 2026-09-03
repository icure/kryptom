"""Independent reference implementation of secp160r1, used only to generate known-answer
vectors for the Kotlin implementation. Python bigints, no cleverness, no constant-time concerns."""

import hashlib
import hmac
import json

# SEC 2 v2, section 2.4.1
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
a  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
b  = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
Gx = 0x4A96B5688EF573284664698968C38BB913CBFC82
Gy = 0x23A628553168947D59DCC912042351377AC5FB32
n  = 0x0100000000000000000001F4C8F927AED3CA752257
h  = 1


def check_parameters():
    assert p == 2**160 - 2**31 - 1, "prime is not 2^160 - 2^31 - 1"
    assert p % 4 == 3, "p must be 3 mod 4 for the sqrt shortcut"
    assert a == (p - 3) % p, "a must be -3 mod p"
    assert p.bit_length() == 160, f"p has {p.bit_length()} bits"
    assert n.bit_length() == 161, f"n has {n.bit_length()} bits"
    # G on curve
    assert (Gy * Gy - (Gx * Gx * Gx + a * Gx + b)) % p == 0, "G is not on the curve"
    # discriminant non-zero
    assert (4 * a**3 + 27 * b**2) % p != 0
    return True


# ---- affine point arithmetic (reference; identity is None) ----

def inv(x):
    return pow(x, p - 2, p)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * inv(2 * y1) % p
    else:
        lam = (y2 - y1) * inv(x2 - x1) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def mul(k, P):
    k %= n
    R = None
    Q = P
    while k:
        if k & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R


def on_curve(x, y):
    return (y * y - (x * x * x + a * x + b)) % p == 0


def decompress(x):
    """Return the even-y point with this x, or None if x is not on the curve."""
    if x >= p:
        return None
    rhs = (x * x * x + a * x + b) % p
    y = pow(rhs, (p + 1) // 4, p)
    if (y * y - rhs) % p != 0:
        return None
    if y % 2 == 1:
        y = p - y
    return (x, y)


G = (Gx, Gy)


# ---- protocol reference ----

LABEL_CODE = b"com.icure.pairing.v1.code"
LABEL_KDF = b"com.icure.pairing.v1.kdf"


def lp(*fields):
    out = b""
    for f in fields:
        out += len(f).to_bytes(4, "big") + f
    return out


def i2osp160(x):
    return x.to_bytes(20, "big")


def code_checksum(version, x_bytes):
    d = hashlib.sha256(lp(LABEL_CODE, bytes([version]), x_bytes)).digest()
    # first 15 bits, big-endian
    return (int.from_bytes(d[:2], "big") >> 1) & 0x7FFF


ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def encode_code(version, x):
    """36 Crockford symbols: 1 version + 32 for x + 3 for a 15-bit checksum."""
    xb = i2osp160(x)
    syms = [version & 0x1F]
    # 160 bits -> 32 symbols, in exact 5-byte/8-symbol blocks
    for blk in range(4):
        chunk = int.from_bytes(xb[blk * 5:(blk + 1) * 5], "big")
        for i in range(7, -1, -1):
            syms.append((chunk >> (5 * i)) & 0x1F)
    c = code_checksum(version, xb)
    for i in range(2, -1, -1):
        syms.append((c >> (5 * i)) & 0x1F)
    assert len(syms) == 36
    s = "".join(ALPHABET[v] for v in syms)
    return "-".join(s[i:i + 4] for i in range(0, 36, 4))


def hkdf(shared_x, transcript, length=64):
    """HKDF-SHA256, salt = empty, info = transcript."""
    prk = hmac.new(b"\x00" * 32, shared_x, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + transcript + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def ecdh_x(scalar, point_x):
    P = decompress(point_x)
    if P is None:
        return None
    R = mul(scalar, P)
    if R is None:
        return None
    return i2osp160(R[0])


def main():
    check_parameters()
    print("domain parameters OK")
    print(f"p  = {p:#x}  ({p.bit_length()} bits)")
    print(f"n  = {n:#x}  ({n.bit_length()} bits)")
    print(f"(p+1)/4 = {(p + 1) // 4:#x}")

    vectors = {
        "domain": {
            "p": f"{p:x}", "a": f"{a:x}", "b": f"{b:x}",
            "gx": f"{Gx:x}", "gy": f"{Gy:x}", "n": f"{n:042x}",
        },
        "field": [],
        "scalarMul": [],
        "decompress": [],
        "ecdh": [],
        "codes": [],
        "kdf": [],
    }

    # --- field vectors: deterministic pseudo-random operands ---
    def prng(seed, count):
        out = []
        s = hashlib.sha256(seed).digest()
        while len(out) < count:
            s = hashlib.sha256(s).digest()
            out.append(int.from_bytes(s, "big") % p)
        return out

    ops = prng(b"field", 40)
    for i in range(0, 40, 2):
        u, v = ops[i], ops[i + 1]
        vectors["field"].append({
            "u": f"{u:040x}", "v": f"{v:040x}",
            "add": f"{(u + v) % p:040x}",
            "sub": f"{(u - v) % p:040x}",
            "mul": f"{u * v % p:040x}",
            "sqr": f"{u * u % p:040x}",
            "inv": f"{inv(u):040x}",
        })
    # edge cases
    for u, v in [(0, 0), (1, 0), (0, 1), (p - 1, p - 1), (p - 1, 1), (1, p - 1),
                 (2, p - 1), (p >> 1, (p >> 1) + 1)]:
        e = {"u": f"{u:040x}", "v": f"{v:040x}",
             "add": f"{(u + v) % p:040x}", "sub": f"{(u - v) % p:040x}",
             "mul": f"{u * v % p:040x}", "sqr": f"{u * u % p:040x}"}
        if u != 0:
            e["inv"] = f"{inv(u):040x}"
        vectors["field"].append(e)

    # --- scalar multiplication ---
    scalars = [1, 2, 3, 4, 7, 255, 256, n - 1, n - 2, (n - 1) // 2,
               0x1234567890ABCDEF1234567890ABCDEF12345678]
    scalars += prng(b"scalars", 8)
    for k in scalars:
        k %= n
        if k == 0:
            continue
        R = mul(k, G)
        vectors["scalarMul"].append({
            "k": f"{k:042x}", "x": f"{R[0]:040x}", "y": f"{R[1]:040x}",
        })

    # --- decompression, valid and invalid ---
    for k in [1, 2, 5, 12345]:
        R = mul(k, G)
        vectors["decompress"].append({"x": f"{R[0]:040x}", "valid": True,
                                      "yEven": f"{decompress(R[0])[1]:040x}"})
    invalid = 0
    cand = 3
    while invalid < 6:
        if decompress(cand) is None:
            vectors["decompress"].append({"x": f"{cand:040x}", "valid": False})
            invalid += 1
        cand += 1
    # x >= p must be rejected
    for bad in [p, p + 1, 2**160 - 1]:
        vectors["decompress"].append({"x": f"{bad:040x}", "valid": False})

    # --- ECDH: both sides must agree ---
    privs = prng(b"ecdh", 12)
    for i in range(0, 12, 2):
        da, db = (privs[i] % (n - 1)) + 1, (privs[i + 1] % (n - 1)) + 1
        Pa, Pb = mul(da, G), mul(db, G)
        sa = ecdh_x(da, Pb[0])
        sb = ecdh_x(db, Pa[0])
        assert sa == sb, "ECDH disagreement in the reference itself"
        vectors["ecdh"].append({
            "dA": f"{da:042x}", "xA": f"{Pa[0]:040x}",
            "dB": f"{db:042x}", "xB": f"{Pb[0]:040x}",
            "sharedX": sa.hex(),
        })

    # --- code encoding ---
    for k in [1, 2, 3, 999, 0xDEADBEEF]:
        R = mul(k, G)
        vectors["codes"].append({
            "version": 1, "x": f"{R[0]:040x}", "code": encode_code(1, R[0]),
            "checksum": code_checksum(1, i2osp160(R[0])),
        })

    # --- KDF ---
    for i, (sx, tr) in enumerate([
        (b"\x00" * 20, b""),
        (i2osp160(mul(3, G)[0]), b"transcript-1"),
        (i2osp160(mul(77, G)[0]), bytes(range(64))),
    ]):
        vectors["kdf"].append({
            "sharedX": sx.hex(), "transcript": tr.hex(),
            "okm64": hkdf(sx, tr, 64).hex(),
        })

    with open("vectors.json", "w") as f:
        json.dump(vectors, f, indent=1)

    counts = {k: len(v) for k, v in vectors.items() if isinstance(v, list)}
    print("vectors written:", counts)
    print("sample code:", vectors["codes"][0]["code"])


if __name__ == "__main__":
    main()
