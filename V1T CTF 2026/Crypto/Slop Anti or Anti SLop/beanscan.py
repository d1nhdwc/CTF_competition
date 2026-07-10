import re, base64, hashlib, sys
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c")); nonce=cup[:12]
def H(x): return hashlib.sha256(x).digest()
bean=[int(x) for x in q("v").split(",")]
# Try coffee = bean, and also each rotation/slice; cream over wide int + fields
def ny(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]==nonce
coffees={"bean":bean}
# also coffee could be the M output applied to bean
m=int(q("m"))
a=bean[10]; xs=bean[4:7]; ids=bean[7:10]; bs=bean[11:14]
Mout=[(x,(a*bean[i]+y)%m) for x,i,y in zip(xs,ids,bs)]
coffees["Mout_pairs"]=[v for p in Mout for v in p]
coffees["Mout_ys"]=[p[1] for p in Mout]
fields=[q(k) for k in ["coffee","sugar","otp","h","cmd","a"]]
ints=[int(q(k)) for k in ["m","r","z","n","d","l"]]
for cn,cf in coffees.items():
    for cr in fields+ints:
        if ny(cf,cr): print("MATCH",cn,"cream=",cr); sys.exit()
    for cr in range(0,500000):
        if ny(cf,cr): print("MATCH",cn,"cream=int",cr); sys.exit()
print("none")
