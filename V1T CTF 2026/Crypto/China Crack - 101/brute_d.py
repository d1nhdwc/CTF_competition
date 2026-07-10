import binascii, os, math, sys
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

base = os.path.dirname(__file__)
ct = binascii.unhexlify(open(os.path.join(base, "extracted", "CC01", "CC01-challenge")).read().strip())

p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC

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

def sm3d(b): return bytes.fromhex(sm3_hash(bytes_to_list(b)))

C1x=int.from_bytes(ct[0:32],"big"); C1y=int.from_bytes(ct[32:64],"big")
C1=(C1x,C1y)
# layouts
C3_a=ct[64:96]; C2_a=ct[96:]          # C1C3C2
C3_b=ct[-32:];  C2_b=ct[64:-32]       # C1C2C3

def full_verify(x2,y2,C3,C2):
    zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
    c=1; t=b""
    while len(t)<len(C2):
        t+=sm3d(zx+zy+c.to_bytes(4,"big")); c+=1
    M=bytes(cc^kk for cc,kk in zip(C2,t[:len(C2)]))
    u=sm3d(zx+M+zy)
    return (u==C3), M

LIMIT = int(sys.argv[1]) if len(sys.argv)>1 else 5_000_000
P = C1  # d=1
report=0
for d in range(1, LIMIT+1):
    x2,y2 = P
    zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
    t1 = sm3d(zx+zy+b"\x00\x00\x00\x01")
    # cheap check both layouts first 8 bytes printable
    for C3,C2 in ((C3_a,C2_a),(C3_b,C2_b)):
        head=bytes(cc^kk for cc,kk in zip(C2[:8],t1[:8]))
        if head[:4] in (b"V1T{",b"v1t{",b"V1t{") or all(32<=x<127 for x in head):
            ok,M=full_verify(x2,y2,C3,C2)
            if ok:
                print(f"*** FOUND d={d} (hex {hex(d)})")
                print("M head:", M[:120])
                sys.exit(0)
    P = padd(P, C1)
    if d % 200000 == 0:
        print("...d=",d, file=sys.stderr)
print("not found up to", LIMIT)
