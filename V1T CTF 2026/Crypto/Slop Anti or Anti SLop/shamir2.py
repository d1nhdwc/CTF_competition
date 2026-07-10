import re
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
m=int(q("m")); bean=[int(x) for x in q("v").split(",")]
def I(v,m):
    s=0
    for i,(x,y) in enumerate(v):
        a=1;b=1
        for j,(u,_) in enumerate(v):
            if i==j: continue
            a=(a*(-u))%m; b=(b*(x-u))%m
        s=(s+y*a*pow(b,-1,m))%m
    return s
# M produces shares; to invert coffee[id]=(share-b)*inv(a). 
# If bean[11:14] are SHARES s_k for ids[6,1,7] with slope a=bean[10], offsets unknown.
# But maybe offsets are 0 and these recover coffee directly:
a=bean[10]
inva=pow(a,-1,m)
ids=bean[7:10]; shares=bean[11:14]
for k,(idx,sh) in enumerate(zip(ids,shares)):
    print(f"coffee[{idx}] = sh*inv(a) =", (sh*inva)%m)
# Also as polynomial: shares at xs=44,58,73 -> interpolate secret
print("secret via I(xs=44/58/73, shares):", I(list(zip(bean[4:7],shares)),m))
# Print all candidate secrets compactly
print("foam m=",m,"bitlen",m.bit_length())
