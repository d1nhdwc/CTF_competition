import binascii, os, sys, hashlib, math
sys.path.insert(0, r"D:\Documents\CTF_competition\V1T CTF 2026\Crypto\China Crack - 202\challenge")
from zuc import ZUC

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = zip_pw + "_V1T"
print("secret len", len(secret), repr(secret))

# sqrt(SMSM): interpret "SMSM" ascii as int, take integer sqrt
smsm_int = int.from_bytes(b"SMSM", "big")
sq = math.isqrt(smsm_int)
print("SMSM int", smsm_int, "isqrt", sq, "hex", hex(sq))

def k16(b):
    if len(b) >= 16: return b[:16]
    return (b + b"\0" * 16)[:16]

key_cands = {
    "SMSMx4": b"SMSM" * 4,
    "secret[:16]": secret.encode()[:16],
    "secret[16:]": secret.encode()[16:32] if len(secret) >= 32 else None,
    "md5secret": hashlib.md5(secret.encode()).digest(),
    "md5SMSM": hashlib.md5(b"SMSM").digest(),
    "sqrtSMSM_be16": k16(sq.to_bytes((sq.bit_length()+7)//8 or 1, "big")),
    "zip[:16]": zip_pw.encode()[:16],
}
iv_cands = {
    "zero": b"\0" * 16,
    "SMSMx4": b"SMSM" * 4,
    "secret[:16]": secret.encode()[:16],
    "secret[16:]": secret.encode()[16:32] if len(secret) >= 32 else None,
    "md5secret": hashlib.md5(secret.encode()).digest(),
    "sqrtSMSM": k16(sq.to_bytes((sq.bit_length()+7)//8 or 1, "big")),
}

def zuc_keystream(key, iv, n):
    z = ZUC(key, iv)
    return z.generate(n)

def good(b):
    return b"V1T{" in b or b"v1t{" in b

hits = 0
for kn, key in key_cands.items():
    if not key or len(key) != 16: continue
    for ivn, iv in iv_cands.items():
        if not iv or len(iv) != 16: continue
        try:
            ks = zuc_keystream(key, iv, len(ct))
            pt = bytes(a ^ b for a, b in zip(ct, ks))
        except Exception as e:
            continue
        if good(pt):
            i = max(pt.find(b"V1T{"), pt.find(b"v1t{"))
            print(f"HIT key={kn} iv={ivn}: {pt[max(0,i-2):i+90]!r}")
            hits += 1
print("done hits", hits)
