import binascii, os
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
    d%= n
    if not d: return None
    x2,y2=pmul(d,C1)
    zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
    res=[]
    for lname,(C3,C2) in layouts.items():
        c=1; t=b""
        while len(t)<len(C2):
            t+=sm3d(zx+zy+c.to_bytes(4,"big")); c+=1
        M=bytes(cc^kk for cc,kk in zip(C2,t))
        if sm3d(zx+M+zy)==C3:
            res.append((lname,M))
    return res

def modsqrt_3mod4(x,m):
    r=pow(x % m,(m+1)//4,m)
    return r if (r*r)%m==x%m else None

# SMSM numeric interpretations
smsm_vals={}
for k in range(1,9):
    smsm_vals[f"SMSMx{k}"]=int.from_bytes(b"SMSM"*k,"big")
smsm_vals["sqrt(SMSM)str"]=int.from_bytes(b"sqrt(SMSM)","big")
smsm_vals["SM"]=int.from_bytes(b"SM","big")
smsm_vals["sm3(SMSM)"]=int.from_bytes(sm3d(b"SMSM"),"big")
smsm_vals["secret"]=int.from_bytes(b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T","big")

cands={}
for name,v in smsm_vals.items():
    for mod,mn in ((p,"p"),(n,"n")):
        r=modsqrt_3mod4(v,mod)
        if r:
            cands[f"modsqrt_{name}_mod{mn}"]=r
            cands[f"modsqrt_{name}_mod{mn}_neg"]=mod-r
    # integer sqrt too
    import math
    cands[f"isqrt_{name}"]=math.isqrt(v)

found=False
for name,d in cands.items():
    r=verify(d)
    if r:
        for lname,M in r:
            print(f"*** FOUND [{name}/{lname}] d={hex(d%n)}")
            print("PLAINTEXT:", M[:300])
            found=True
print("found:", found, "tested", len(cands))
