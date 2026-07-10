import re, hashlib, base64, sys
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c")); nonce=cup[:12]
def H(x): return hashlib.sha256(x).digest()
def ny(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]==nonce
m=int(q("m")); bean=[int(x) for x in q("v").split(",")]; n=int(q("n")); r=int(q("r")); zz=int(q("z"))
def M(coffee,v,m):
    a=v[10]; xs=v[4:7]; ids=v[7:10]; bs=v[11:14]
    return [(x,(a*coffee[i]+y)%m) for x,i,y in zip(xs,ids,bs)]
# coffee=M(bean,bean,m)
cm=M(bean,bean,m)
print("M(bean,bean,m)=",cm)
coffees={"Mbean":cm,"Mbean_ys":[p[1] for p in cm],"Mbean_flat":[v for p in cm for v in p]}
creams=[m,n,r,zz,q("coffee"),q("sugar")]
for cn,cf in coffees.items():
    for cr in creams:
        if ny(cf,cr): print("NONCE MATCH",cn,"cream=",cr); sys.exit()
    # also cream small ints
    for cr in range(0,100000):
        if ny(cf,cr): print("NONCE MATCH",cn,"cream=int",cr); sys.exit()
print("no match")
