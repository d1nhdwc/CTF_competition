import binascii, os, math
from gmssl import sm2
from gmssl.sm3 import sm3_hash
from gmssl.func import bytes_to_list

p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

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
def sm3d(bb): return bytes.fromhex(sm3_hash(bytes_to_list(bb)))
def kdf(z,klen):
    c=1; out=b""
    while len(out)<klen:
        out+=sm3d(z+c.to_bytes(4,"big")); c+=1
    return out[:klen]
def my_decrypt(ct, d, mode):
    C1x=int.from_bytes(ct[0:32],"big"); C1y=int.from_bytes(ct[32:64],"big")
    if mode:  # C1C3C2
        C3=ct[64:96]; C2=ct[96:]
    else:     # C1C2C3
        C3=ct[-32:]; C2=ct[64:-32]
    x2,y2=pmul(d,(C1x,C1y))
    zx=x2.to_bytes(32,"big"); zy=y2.to_bytes(32,"big")
    t=kdf(zx+zy,len(C2))
    M=bytes(cc^kk for cc,kk in zip(C2,t))
    u=sm3d(zx+M+zy)
    return M, u==C3

# roundtrip with gmssl
for gmode in (0,1):
    d=37384
    P=pmul(d,(Gx,Gy))
    pub=format(P[0],"064x")+format(P[1],"064x")
    priv=format(d,"064x")
    crypt=sm2.CryptSM2(public_key=pub, private_key=priv, mode=gmode)
    msg=b"V1T{test_roundtrip_message}"
    enc=crypt.encrypt(msg)
    M,ok=my_decrypt(enc, d, gmode)
    print(f"gmode={gmode} my_decrypt ok={ok} M={M!r}")
