import binascii, os, hashlib, itertools, math, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = zip_pw + "_V1T"            # 32 bytes
hint = "sqrt(SMSM)"

def sm3d(b):
    return bytes.fromhex(sm3_hash(bytes_to_list(b)))

def k16(b):
    return (b + b"\0" * 16)[:16] if len(b) < 16 else b[:16]

# ---- build key candidates (16 bytes) ----
sources = {
    "SMSMx4": b"SMSM" * 4,
    "secret[:16]": secret.encode()[:16],
    "secret[16:]": secret.encode()[16:],
    "secretlast16": secret.encode()[-16:],
    "zip[:16]": zip_pw.encode()[:16],
    "hint_pad": k16(hint.encode()),
    "md5secret": hashlib.md5(secret.encode()).digest(),
    "md5zip": hashlib.md5(zip_pw.encode()).digest(),
    "md5SMSM": hashlib.md5(b"SMSM").digest(),
    "md5SMSMx4": hashlib.md5(b"SMSM" * 4).digest(),
    "md5hint": hashlib.md5(hint.encode()).digest(),
    "sm3secret16": sm3d(secret.encode())[:16],
    "sm3zip16": sm3d(zip_pw.encode())[:16],
    "sm3SMSM16": sm3d(b"SMSM")[:16],
    "sm3SMSMx4_16": sm3d(b"SMSM" * 4)[:16],
    "sm3hint16": sm3d(hint.encode())[:16],
    "sm3secret_last16": sm3d(secret.encode())[16:],
    "sha256secret16": hashlib.sha256(secret.encode()).digest()[:16],
    "sha256hint16": hashlib.sha256(hint.encode()).digest()[:16],
}
keys = {n: v for n, v in sources.items() if v and len(v) == 16}

# ---- IV candidates ----
ivs = {
    "zero": b"\0" * 16,
    "SMSMx4": b"SMSM" * 4,
    "secret[:16]": secret.encode()[:16],
    "secret[16:]": secret.encode()[16:],
    "hint_pad": k16(hint.encode()),
    "md5secret": hashlib.md5(secret.encode()).digest(),
    "sm3secret16": sm3d(secret.encode())[:16],
}
ivs = {n: v for n, v in ivs.items() if v and len(v) == 16}

def score(b):
    if b"V1T{" in b or b"v1t{" in b or b"V1t{" in b:
        return 100
    # printable ratio
    pr = sum(1 for x in b[:200] if 9 <= x <= 126) / min(200, len(b))
    return pr

ct16 = ct[: len(ct) - len(ct) % 16]
best = []
for kn, key in keys.items():
    for ivn, iv in ivs.items():
        trials = [
            ("ECB", modes.ECB(), ct16),
            ("CBC", modes.CBC(iv), ct16),
            ("CTR", modes.CTR(iv), ct),
            ("OFB", modes.OFB(iv), ct),
            ("CFB", modes.CFB(iv), ct),
            ("CFB8", modes.CFB8(iv), ct),
        ]
        for mn, mode, data in trials:
            try:
                d = Cipher(algorithms.SM4(key), mode).decryptor()
                pt = d.update(data) + d.finalize()
            except Exception:
                continue
            s = score(pt)
            if s >= 100:
                i = max(pt.find(b"V1T{"), pt.find(b"v1t{"), pt.find(b"V1t{"))
                print(f"*** FLAG HIT {kn}/{ivn}/{mn}: {pt[max(0,i-2):i+90]!r}")
            best.append((s, kn, ivn, mn, pt[:48]))

best.sort(reverse=True)
print("=== top printable candidates ===")
for s, kn, ivn, mn, pre in best[:8]:
    print(round(s, 2), kn, ivn, mn, pre)
