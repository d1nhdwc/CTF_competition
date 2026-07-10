from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list
import binascii, hashlib, os, itertools

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = zip_pw + "_V1T"

def sm3d(b):
    return bytes.fromhex(sm3_hash(bytes_to_list(b)))

# 16-byte key candidates
keys = {}
keys["SMSMx4"] = b"SMSM" * 4
keys["secret16"] = secret.encode()[:16]
keys["zip16"] = zip_pw.encode()[:16]
keys["md5secret"] = hashlib.md5(secret.encode()).digest()
keys["md5zip"] = hashlib.md5(zip_pw.encode()).digest()
keys["sm3secret16"] = sm3d(secret.encode())[:16]
keys["sm3zip16"] = sm3d(zip_pw.encode())[:16]
keys["sm3SMSM16"] = sm3d(b"SMSM")[:16]
keys["secretpad"] = (secret.encode() + b"\x00"*16)[:16]

ivs = {
    "zero": b"\x00"*16,
    "SMSMx4": b"SMSM"*4,
    "md5secret": hashlib.md5(secret.encode()).digest(),
    "secret16": secret.encode()[:16],
}

def sm4_ecb_enc_block(key, block):
    c = CryptSM4(); c.set_key(key, SM4_ENCRYPT); return c.crypt_ecb(block)

def ctr(key, iv, data):
    out = bytearray(); ctr_i = int.from_bytes(iv, "big")
    for i in range(0, len(data), 16):
        ks = sm4_ecb_enc_block(key, (ctr_i & ((1<<128)-1)).to_bytes(16, "big"))
        chunk = data[i:i+16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr_i += 1
    return bytes(out)

def ofb(key, iv, data):
    out = bytearray(); fb = iv
    for i in range(0, len(data), 16):
        fb = sm4_ecb_enc_block(key, fb)
        chunk = data[i:i+16]
        out += bytes(a ^ b for a, b in zip(chunk, fb))
    return bytes(out)

def cfb(key, iv, data):
    out = bytearray(); fb = iv
    for i in range(0, len(data), 16):
        ks = sm4_ecb_enc_block(key, fb)
        chunk = data[i:i+16]
        p = bytes(a ^ b for a, b in zip(chunk, ks))
        out += p; fb = chunk + ks[len(chunk):]
    return bytes(out)

def good(b):
    return b"V1T{" in b or b"v1t{" in b or b"flag" in b.lower()

hits = 0
for kn, k in keys.items():
    for ivn, iv in ivs.items():
        for mn, fn in (("CTR", ctr), ("OFB", ofb), ("CFB", cfb)):
            try:
                pt = fn(k, iv, ct)
                if good(pt):
                    print(f"HIT {kn}/{ivn}/{mn}: {pt[:120]!r}")
                    hits += 1
            except Exception as e:
                pass
print("done hits", hits)
