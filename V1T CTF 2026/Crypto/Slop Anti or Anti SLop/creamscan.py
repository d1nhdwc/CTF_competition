import re, base64, hashlib
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c")); nonce=cup[:12]
bean=[int(x) for x in q("v").split(",")]; foam=int(q("m"))
blend=[bean[0],bean[2],5,len(cup),foam.bit_length()]
def H(x): return hashlib.sha256(x).digest()
xenc=",".join(map(str,blend)).encode()
base=b"drip"+H(xenc)+b"cream"
def chk(cream):
    return hashlib.sha256(base+H(str(cream).encode())).digest()[:12]==nonce
m=int(q("m")); n=int(q("n")); r=int(q("r")); zz=int(q("z"))
# candidate creams
cands={}
cands["r"]=r; cands["z"]=zz; cands["n"]=n; cands["m"]=m
def I(v,m):
    s=0
    for i,(x,y) in enumerate(v):
        a=1;b=1
        for j,(u,_) in enumerate(v):
            if i==j: continue
            a=(a*(-u))%m; b=(b*(x-u))%m
        s=(s+y*a*pow(b,-1,m))%m
    return s
a=bean[10]; xs=bean[4:7]; ids=bean[7:10]; bs=bean[11:14]
cands["I_xs_bs"]=I(list(zip(xs,bs)),m)
cands["I_ids_bs"]=I(list(zip(ids,bs)),m)
# coffee[id] recovery via M inverse: coffee[i]=(y-b)/a ... but need y. skip
# time-lock small bases
for g in [2,3,5,bean[1],bean[3]]:
    cands[f"R{g}"]=pow(g, pow(2,zz,n-1) if False else 1, n)  # placeholder
# actual time-lock too slow (70M sq) - skip full, but try g^(2^z) via pow with known order? unknown.
for k,v in cands.items():
    if chk(v):
        print("CREAM MATCH", k, v)
# also try string fields
for k in ["coffee","sugar","otp","h","cmd","d","l"]:
    if chk(q(k)):
        print("CREAM MATCH field", k, q(k))
print("done; blend-as-coffee tested")
