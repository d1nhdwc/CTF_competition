import binascii, os, math, hashlib
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())

p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

def inv(x,m): return pow(x,m-2,m)
def padd(P,Q):
    if P is None: return Q
    if Q is None: return P
    (x1,y1),(x2,y2)=P,Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P==Q: l=(3*x1*x1+a)*inv(2*y1,p)%p
    else: l=(y2-y1)*inv((x2-x1)%p,p)%p
    x3=(l*l-x1-x2)%p; y3=(l*(x1-x3)-y1)%p
    return (x3,y3)
def pmul(k,P):
    R=None
    while k:
        if k&1: R=padd(R,P)
        P=padd(P,P); k>>=1
    return R
def sm3d(b): return bytes.fromhex(sm3_hash(bytes_to_list(b)))
def kdf(z,klen):
    c=1; out=b""
    while len(out)<klen:
        out+=sm3d(z+c.to_bytes(4,"big")); c+=1
    return out[:klen]

C1x=int.from_bytes(ct[0:32],"big"); C1y=int.from_bytes(ct[32:64],"big")
on=(C1y*C1y-(C1x**3+a*C1x+b))%p==0
print("C1 on curve:", on)

# two layouts
layouts = {
    "C1C3C2": (ct[64:96], ct[96:]),
    "C1C2C3": (ct[-32:], ct[64:-32]),
}

def check(d):
    x2,y2=pmul(d,(C1x,C1y))
    zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
    res=[]
    for lname,(C3,C2) in layouts.items():
        t=kdf(zx+zy,len(C2))
        M=bytes(cc^kk for cc,kk in zip(C2,t))
        u=sm3d(zx+M+zy)
        if u==C3: res.append((lname,M))
    return res

cands={}
for k in range(1,65):
    cands[f"isqrt_SMSMx{k}"]=math.isqrt(int.from_bytes(b"SMSM"*k,"big"))
cands["isqrt_n"]=math.isqrt(n)
cands["isqrt_p"]=math.isqrt(p)
cands["isqrt_secret"]=math.isqrt(int.from_bytes(b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T","big"))

found=False
for name,d in cands.items():
    d%=n
    if not d: continue
    for lname,M in check(d):
        print(f"*** HIT [{name}/{lname}] d={hex(d)} M={M[:200]!r}")
        found=True
print("candidate phase found:", found)
