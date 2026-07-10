import binascii, os, hashlib, math, struct, zlib, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list
sys.path.insert(0, r"D:\Documents\CTF_competition\V1T CTF 2026\Crypto\China Crack - 202\challenge")
from zuc import ZUC

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = (zip_pw + "_V1T").encode()       # 32 bytes
hint = b"sqrt(SMSM)"

def sm3d(b): return bytes.fromhex(sm3_hash(bytes_to_list(b)))
def k16(b): return (b + b"\0"*16)[:16]
def k32(b): return (b + b"\0"*32)[:32]

# sqrt-derived material
def isqrt_bytes(b):
    n = int.from_bytes(b, "big")
    s = math.isqrt(n)
    return s.to_bytes((s.bit_length()+7)//8 or 1, "big")

sqrt_srcs = {
    "sqrt_SMSM": isqrt_bytes(b"SMSM"),
    "sqrt_SMSMx4": isqrt_bytes(b"SMSM"*4),
    "sqrt_SMSMx2": isqrt_bytes(b"SMSM"*2),
    "sqrt_secret": isqrt_bytes(secret),
}

# big pool of 16-byte keys
keypool = {}
def add(name, b):
    if b: keypool[name] = b

add("SMSMx4", b"SMSM"*4)
add("secret16", secret[:16]); add("secretL16", secret[-16:]); add("secretH16", secret[16:])
add("zip16", zip_pw.encode()[:16])
add("hint16", k16(hint))
add("md5secret", hashlib.md5(secret).digest())
add("md5zip", hashlib.md5(zip_pw.encode()).digest())
add("md5hint", hashlib.md5(hint).digest())
add("md5SMSM", hashlib.md5(b"SMSM").digest())
add("md5SMSMx4", hashlib.md5(b"SMSM"*4).digest())
add("sm3secret16", sm3d(secret)[:16]); add("sm3secretL16", sm3d(secret)[-16:])
add("sm3zip16", sm3d(zip_pw.encode())[:16])
add("sm3hint16", sm3d(hint)[:16])
add("sm3SMSM16", sm3d(b"SMSM")[:16])
add("sha256secret16", hashlib.sha256(secret).digest()[:16])
add("sha256hint16", hashlib.sha256(hint).digest()[:16])
for n,s in sqrt_srcs.items():
    add(n+"_pad", k16(s)); add(n+"_md5", hashlib.md5(s).digest()); add(n+"_sm3_16", sm3d(s)[:16])

keys16 = {n:v for n,v in keypool.items() if len(v)>=16}
keys16 = {n:v[:16] for n,v in keys16.items()}

# IVs
ivpool = {"zero": b"\0"*16, "SMSMx4": b"SMSM"*4, "secret16": secret[:16],
          "secretH16": secret[16:], "hint16": k16(hint),
          "md5secret": hashlib.md5(secret).digest(), "sm3secret16": sm3d(secret)[:16],
          "sqrtSMSM": k16(sqrt_srcs["sqrt_SMSM"])}
ivs = {n:v[:16] for n,v in ivpool.items()}

def report(tag, pt):
    for marker in (b"V1T{", b"v1t{", b"V1t{"):
        i = pt.find(marker)
        if i>=0:
            print(f"*** {tag}: {pt[i:i+100]!r}")
            return True
    # try zlib
    for off in (0,):
        try:
            d = zlib.decompress(pt)
            for marker in (b"V1T{", b"v1t{", b"V1t{"):
                i = d.find(marker)
                if i>=0:
                    print(f"*** {tag} [zlib]: {d[i:i+100]!r}")
                    return True
        except Exception: pass
    return False

ct16 = ct[:len(ct)-len(ct)%16]
found = False

# RC4
def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&255; S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for c in data:
        i=(i+1)&255; j=(j+S[i])&255; S[i],S[j]=S[j],S[i]
        out.append(c ^ S[(S[i]+S[j])&255])
    return bytes(out)

for kn,key in keys16.items():
    # RC4 (variable key len ok, use raw key sources too)
    if report(f"RC4/{kn}", rc4(key, ct)): found=True
    # ZUC needs 16 key+16 iv
    for ivn,iv in ivs.items():
        try:
            ks = ZUC(key, iv).generate(len(ct))
            if report(f"ZUC/{kn}/{ivn}", bytes(a^b for a,b in zip(ct,ks))): found=True
        except Exception: pass
        for mn,mode,data in (("ECB",modes.ECB(),ct16),("CBC",modes.CBC(iv),ct16),
                             ("CTR",modes.CTR(iv),ct),("OFB",modes.OFB(iv),ct),
                             ("CFB",modes.CFB(iv),ct),("CFB8",modes.CFB8(iv),ct)):
            for alg,an in ((algorithms.SM4,"SM4"),(algorithms.AES,"AES")):
                try:
                    d=Cipher(alg(key),mode).decryptor(); pt=d.update(data)+d.finalize()
                    if report(f"{an}/{kn}/{ivn}/{mn}", pt): found=True
                except Exception: pass

print("scan complete, found:", found)
