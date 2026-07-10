from gmssl.sm4 import CryptSM4, SM4_DECRYPT
import binascii, hashlib, os

base = os.path.dirname(__file__)
hexdata = open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip()
ct = binascii.unhexlify(hexdata)
print("ct len", len(ct), "mod16", len(ct) % 16)

zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = zip_pw + "_V1T"  # from filename hint
hint = "sqrt(SMSM)"

# candidate 16-byte SM4 keys
def k16(s):
    b = s.encode()
    return (b * (16 // len(b) + 1))[:16] if b else b"\x00" * 16

cands = {
    "SMSMx4": b"SMSM" * 4,
    "SMSMSMSM(8)x2": b"SMSMSMSM" * 2,
    "secret16": secret.encode()[:16],
    "secret_last16": secret.encode()[-16:],
    "zip16": zip_pw.encode()[:16],
    "md5(secret)": hashlib.md5(secret.encode()).digest(),
    "md5(SMSM)": hashlib.md5(b"SMSM").digest(),
    "md5(zip)": hashlib.md5(zip_pw.encode()).digest(),
    "sm3(secret)": None,  # filled below
}
try:
    from gmssl.sm3 import sm3_hash
    from gmssl.func import bytes_to_list
    cands["sm3(secret)16"] = bytes.fromhex(sm3_hash(bytes_to_list(secret.encode())))[:16]
    cands["sm3(SMSM)16"] = bytes.fromhex(sm3_hash(bytes_to_list(b"SMSM")))[:16]
except Exception as e:
    print("sm3 err", e)

def looks_flag(b):
    return b"V1T{" in b or b"v1t{" in b or b"flag" in b.lower()

ct16 = ct[: len(ct) - (len(ct) % 16)]
for name, key in cands.items():
    if not key:
        continue
    for mode_name in ("ECB", "CBC"):
        try:
            c = CryptSM4()
            c.set_key(key, SM4_DECRYPT)
            if mode_name == "ECB":
                pt = c.crypt_ecb(ct16)
            else:
                pt = c.crypt_cbc(b"\x00" * 16, ct16)
            if looks_flag(pt) or all(32 <= x < 127 for x in pt[:16]):
                print(f"[{name}/{mode_name}] {pt[:80]!r}")
        except Exception as e:
            pass
print("done")
