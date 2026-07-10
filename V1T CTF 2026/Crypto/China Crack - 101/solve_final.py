import binascii, os, math
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

def inv(x,m): return pow(x,m-2,m)
def padd(P,Q):
    if P is None: return Q
    if Q is None: return P
    (x1,y1),(x2,y2)=P,Q
    if x1==x2 and (y1+y2)%p==0: return None
    if x1==x2 and y1==y2: l=(3*x1*x1+a)*inv(2*y1,p)%p
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

C1=(int.from_bytes(ct[0:32],"big"), int.from_bytes(ct[32:64],"big"))
layouts={"C1C3C2":(ct[64:96],ct[96:]), "C1C2C3":(ct[-32:],ct[64:-32])}
def verify(d):
    d%=n
    if not d: return []
    x2,y2=pmul(d,C1)
    zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
    t1=sm3d(zx+zy+b"\x00\x00\x00\x01")
    out=[]
    for lname,(C3,C2) in layouts.items():
        head=bytes(cc^kk for cc,kk in zip(C2[:16],t1[:16]))
        if not (head[:4] in (b"V1T{",b"v1t{",b"V1t{") or all(32<=x<127 for x in head[:6])):
            continue
        c=1; t=b""
        while len(t)<len(C2): t+=sm3d(zx+zy+c.to_bytes(4,"big")); c+=1
        M=bytes(cc^kk for cc,kk in zip(C2,t))
        if sm3d(zx+M+zy)==C3: out.append((lname,M))
    return out
def msqrt(x,m):
    r=pow(x%m,(m+1)//4,m)
    return r if (r*r)%m==x%m else None

strings = {
    "SMSM": b"SMSM", "SMSMx2": b"SMSM"*2, "SMSMx4": b"SMSM"*4, "SMSMx8": b"SMSM"*8,
    "SM": b"SM", "SMx16": b"SM"*16, "sqrt(SMSM)": b"sqrt(SMSM)",
    "SM2SM3SM4": b"SM2SM3SM4", "secret": b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T",
    "ShangMi": b"ShangMi", "shangmi": b"shangmi", "smsm_lower": b"smsm",
}
cands={}
for name,s in strings.items():
    v=int.from_bytes(s,"big")
    cands[f"int_{name}"]=v
    cands[f"isqrt_{name}"]=math.isqrt(v)
    cands[f"sm3_{name}"]=int.from_bytes(sm3d(s),"big")
    for mod,mn in ((p,"p"),(n,"n")):
        r=msqrt(v,mod)
        if r: cands[f"msqrt_{name}_{mn}"]=r; cands[f"msqrt_{name}_{mn}_neg"]=mod-r
        r2=msqrt(int.from_bytes(sm3d(s),"big"),mod)
        if r2: cands[f"msqrtsm3_{name}_{mn}"]=r2
# small ints
for d in list(range(1,256))+[37384, 0x534D, 0x534D534D]:
    cands[f"small_{d}"]=d

found=False
for name,d in cands.items():
    for lname,M in verify(d):
        print(f"*** FOUND [{name}/{lname}] d={hex(d%n)}")
        print("PLAINTEXT:", M[:400])
        found=True
print("found:", found, "tested", len(cands))
