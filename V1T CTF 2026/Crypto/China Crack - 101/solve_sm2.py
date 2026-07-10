import binascii, os, math, hashlib
from gmssl import sm2, func
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
print("len", len(ct), "C2 len", len(ct) - 96)

N = 0xFFFFFFFEFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123  # placeholder, real below
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

def sm3d(b): return bytes.fromhex(sm3_hash(bytes_to_list(b)))

# private key candidates as integers
cands = {}
def addn(name, v):
    if isinstance(v, bytes): v = int.from_bytes(v, "big")
    if 1 <= v < n: cands[name] = v

addn("isqrt_SMSM", math.isqrt(int.from_bytes(b"SMSM","big")))
addn("isqrt_SMSMx2", math.isqrt(int.from_bytes(b"SMSM"*2,"big")))
addn("isqrt_SMSMx4", math.isqrt(int.from_bytes(b"SMSM"*4,"big")))
addn("isqrt_SMSMx8", math.isqrt(int.from_bytes(b"SMSM"*8,"big")))
addn("SMSM", b"SMSM")
addn("SMSMx4", b"SMSM"*4)
addn("SMSMx8", b"SMSM"*8)
addn("sm3_SMSM", sm3d(b"SMSM"))
addn("sm3_SMSMx4", sm3d(b"SMSM"*4))
addn("sm3_sqrtSMSM", sm3d(b"sqrt(SMSM)"))
addn("sm3_secret", sm3d(b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T"))
addn("md5_sqrtSMSM", hashlib.md5(b"sqrt(SMSM)").digest())
addn("sqrtSMSM_str", b"sqrt(SMSM)")
addn("isqrt_secret", math.isqrt(int.from_bytes(b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T","big")))

# gmssl decrypt needs public key set too, but for decrypt only private_key is used.
def try_priv(d, mode):
    priv_hex = format(d, "064x")
    crypt = sm2.CryptSM2(public_key="", private_key=priv_hex, mode=mode)
    try:
        pt = crypt.decrypt(ct)
        return pt
    except Exception:
        return None

def good(pt):
    return pt and (b"V1T{" in pt or b"v1t{" in pt or b"V1t{" in pt or all(32<=c<127 for c in pt[:20]))

for name, d in cands.items():
    for mode in (0, 1):
        pt = try_priv(d, mode)
        if pt:
            tag = "FLAG" if (b"V1T{" in pt or b"v1t{" in pt or b"V1t{" in pt) else "ok"
            print(f"[{tag}] [{name}/mode{mode}] d={hex(d)} -> {pt[:120]!r}")
