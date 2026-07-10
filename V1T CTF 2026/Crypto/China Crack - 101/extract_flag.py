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

d = int.from_bytes(b"D4mn_br0_H0n3y_p07_7yp3_5h1d_V1T","big") % n
C1=(int.from_bytes(ct[0:32],"big"), int.from_bytes(ct[32:64],"big"))
C3=ct[-32:]; C2=ct[64:-32]   # C1C2C3
x2,y2=pmul(d,C1)
zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
c=1; t=b""
while len(t)<len(C2): t+=sm3d(zx+zy+c.to_bytes(4,"big")); c+=1
hexstr=bytes(cc^kk for cc,kk in zip(C2,t))
assert sm3d(zx+hexstr+zy)==C3
# plaintext was hex-encoded PNG
png=binascii.unhexlify(hexstr.decode())
out=os.path.join(base, "flag.png")
open(out,"wb").write(png)
print("wrote", out, len(png), "bytes; PNG sig:", png[:8].hex())
