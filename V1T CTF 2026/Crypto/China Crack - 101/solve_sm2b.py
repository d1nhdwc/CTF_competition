import binascii, os, math, hashlib
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())

# SM2 / sm2p256v1 params
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

def inv(x, m): return pow(x, m-2, m)
def padd(P, Q):
    if P is None: return Q
    if Q is None: return P
    (x1,y1),(x2,y2)=P,Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P==Q:
        l=(3*x1*x1+a)*inv(2*y1,p)%p
    else:
        l=(y2-y1)*inv(x2-x1,p)%p
    x3=(l*l-x1-x2)%p; y3=(l*(x1-x3)-y1)%p
    return (x3,y3)
def pmul(k,P):
    R=None
    while k:
        if k&1: R=padd(R,P)
        P=padd(P,P); k>>=1
    return R

def sm3d(b): return bytes.fromhex(sm3_hash(bytes_to_list(b)))

def kdf(z, klen):
    ct_=1; out=b""
    while len(out)<klen:
        out += sm3d(z + ct_.to_bytes(4,"big"))
        ct_+=1
    return out[:klen]

# parse C1C3C2
C1x=int.from_bytes(ct[0:32],"big"); C1y=int.from_bytes(ct[32:64],"big")
C3=ct[64:96]; C2=ct[96:]
assert (C1y*C1y-(C1x**3+a*C1x+b))%p==0, "C1 not on curve"

def decrypt_with_d(d):
    x2,y2 = pmul(d,(C1x,C1y))
    z = x2.to_bytes(32,"big")+y2.to_bytes(32,"big")
    t = kdf(z, len(C2))
    M = bytes(c^k for c,k in zip(C2,t))
    u = sm3d(x2.to_bytes(32,"big")+M+y2.to_bytes(32,"big"))
    return M, (u==C3)

# candidate private keys
cands = {}
for k in range(1,33):
    src=(b"SMSM"*k)
    cands[f"isqrt_SMSMx{k}"]=math.isqrt(int.from_bytes(src,"big"))
cands["isqrt_secret"]=math.isqrt(int.from_bytes(b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T","big"))
cands["isqrt_sqrtstr"]=math.isqrt(int.from_bytes(b"sqrt(SMSM)","big"))
cands["SMSM_int"]=int.from_bytes(b"SMSM","big")
cands["sm3_sqrtSMSM"]=int.from_bytes(sm3d(b"sqrt(SMSM)"),"big")%n

found=False
for name,d in cands.items():
    d%= n
    if d==0: continue
    M,ok=decrypt_with_d(d)
    if ok:
        print(f"*** C3 VALID [{name}] d={hex(d)}")
        print("PLAINTEXT:", M[:200])
        found=True
if not found:
    print("no C3 match among candidates")
