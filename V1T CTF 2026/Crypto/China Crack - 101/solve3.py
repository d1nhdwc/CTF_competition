import binascii, os, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = zip_pw + "_V1T"

def sm3d(b):
    return bytes.fromhex(sm3_hash(bytes_to_list(b)))

keys = {}
for name, src in [("SMSMx4", b"SMSM" * 4), ("secret16", secret.encode()[:16]),
                  ("secretlast16", secret.encode()[-16:]), ("zip16", zip_pw.encode()[:16]),
                  ("md5secret", hashlib.md5(secret.encode()).digest()),
                  ("md5zip", hashlib.md5(zip_pw.encode()).digest()),
                  ("md5SMSM", hashlib.md5(b"SMSM").digest()),
                  ("sm3secret16", sm3d(secret.encode())[:16]),
                  ("sm3zip16", sm3d(zip_pw.encode())[:16]),
                  ("sm3SMSM16", sm3d(b"SMSM")[:16]),
                  ("sm3SMSMSMSM16", sm3d(b"SMSM" * 4)[:16]),
                  ("secretpad0", (secret.encode() + b"\0" * 16)[:16])]:
    keys[name] = src

ivs = {"zero": b"\0" * 16, "SMSMx4": b"SMSM" * 4, "secret16": secret.encode()[:16],
       "md5secret": hashlib.md5(secret.encode()).digest(), "sm3secret16": sm3d(secret.encode())[:16]}

def good(b):
    return b"V1T{" in b or b"v1t{" in b

ct16 = ct[: len(ct) - len(ct) % 16]
hits = 0
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
            if good(pt):
                i = max(pt.find(b"V1T{"), pt.find(b"v1t{"))
                print(f"HIT {kn}/{ivn}/{mn}: {pt[max(0,i-2):i+80]!r}")
                hits += 1
print("done, hits", hits)
