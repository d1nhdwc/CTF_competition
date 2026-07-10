import re, hashlib, base64, sys
from decimal import Decimal
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c")); nonce=cup[:12]
def H(x): return hashlib.sha256(x).digest()
def ny(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]==nonce
roast=[(Decimal(x),Decimal(y)) for x,y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
m=int(q("m")); n=int(q("n")); r=int(q("r")); zz=int(q("z"))
# coffee = roast (list of tuples)
coffees={
 "roast_tuples":roast,
 "roast_xs":[p[0] for p in roast],
 "roast_ys":[p[1] for p in roast],
 "roast_flat":[v for p in roast for v in p],
}
creams=[m,n,r,zz,q("coffee"),q("sugar"),q("otp")]
for cn,cf in coffees.items():
    for cr in creams:
        if ny(cf,cr): print("MATCH",cn,"cream=",cr); sys.exit()
    for cr in range(0,50000):
        if ny(cf,cr): print("MATCH",cn,"cream=int",cr); sys.exit()
print("no roast match")
# show how str of a tuple looks
print("sample str:", str(roast[0])[:80])
