import binascii, os, hashlib, math, sys, zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list
sys.path.insert(0, r"D:\Documents\CTF_competition\V1T CTF 2026\Crypto\China Crack - 202\challenge")
from zuc import ZUC

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
zip_pw = "D4mn_br0_H0n3y_p07_7yp3_5h1d"
secret = (zip_pw + "_V1T").encode()
hint = b"sqrt(SMSM)"
def sm3d(b): return bytes.fromhex(sm3_hash(bytes_to_list(b)))
def k16(b): return (b+b"\0"*16)[:16]

def report(tag, pt):
    for m in (b"V1T{", b"v1t{", b"V1t{"):
        i = pt.find(m)
        if i>=0:
            print(f"*** {tag}: {pt[i:i+100]!r}"); return True
    try:
        d=zlib.decompress(pt)
        for m in (b"V1T{", b"v1t{", b"V1t{"):
            i=d.find(m)
            if i>=0: print(f"*** {tag}[zlib]: {d[i:i+100]!r}"); return True
    except Exception: pass
    return False

# key/iv pairs to try (key16, iv16)
pairs = []
sm3s = sm3d(secret)
pairs.append(("sm3secret_split", sm3s[:16], sm3s[16:]))
sm3z = sm3d(zip_pw.encode())
pairs.append(("sm3zip_split", sm3z[:16], sm3z[16:]))
pairs.append(("secret_split", secret[:16], secret[16:]))
md5s = hashlib.md5(secret).digest()
pairs.append(("md5secret_dup", md5s, md5s))
# sqrt string forms
smsm_sqrt = math.isqrt(int.from_bytes(b"SMSM","big"))
for sform in (str(smsm_sqrt).encode(), hex(smsm_sqrt).encode(), format(smsm_sqrt,"x").encode(), smsm_sqrt.to_bytes(2,"big")):
    pairs.append((f"sqrtstr_{sform}", k16(sform), k16(sform)))
    pairs.append((f"md5sqrtstr_{sform}", hashlib.md5(sform).digest(), b"\0"*16))
    pairs.append((f"sm3sqrtstr_{sform}", sm3d(sform)[:16], sm3d(sform)[16:]))
# PBKDF2 with various salts/iters
for salt_name, salt in (("none", b""), ("V1T", b"_V1T"), ("SMSM", b"SMSM"), ("hint", hint), ("zip", zip_pw.encode())):
    for iters in (1000, 10000, 100000):
        try:
            dk = PBKDF2HMAC(hashes.SHA256(), 32, salt, iters).derive(secret)
            pairs.append((f"pbkdf2_{salt_name}_{iters}", dk[:16], dk[16:]))
        except Exception: pass

bodies = {"full": ct, "ivpre": ct[16:]}  # ivpre uses ct[:16] as IV

def runmode(an, alg, key, iv, data, tag):
    out=False
    d16 = data[:len(data)-len(data)%16]
    for mn,mode,dd in (("ECB",modes.ECB(),d16),("CBC",modes.CBC(iv),d16),
                       ("CTR",modes.CTR(iv),data),("OFB",modes.OFB(iv),data),
                       ("CFB",modes.CFB(iv),data),("CFB8",modes.CFB8(iv),data)):
        try:
            dec=Cipher(alg(key),mode).decryptor(); pt=dec.update(dd)+dec.finalize()
            if report(f"{an}/{tag}/{mn}", pt): out=True
        except Exception: pass
    return out

found=False
for pn, key, iv in pairs:
    if len(key)!=16: continue
    iv = (iv+b"\0"*16)[:16]
    # full body, given iv
    for alg,an in ((algorithms.SM4,"SM4"),(algorithms.AES,"AES")):
        if runmode(an, alg, key, iv, ct, pn+"/full"): found=True
    # iv prepended in ciphertext
    ivp = ct[:16]
    for alg,an in ((algorithms.SM4,"SM4"),(algorithms.AES,"AES")):
        if runmode(an, alg, key, ivp, ct[16:], pn+"/ivpre"): found=True
    # ZUC
    try:
        ks=ZUC(key,iv).generate(len(ct)); 
        if report(f"ZUC/{pn}", bytes(a^b for a,b in zip(ct,ks))): found=True
    except Exception: pass

print("done found:", found)
