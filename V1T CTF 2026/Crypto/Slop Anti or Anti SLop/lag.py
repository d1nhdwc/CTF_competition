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
a=bean[10]; xs=bean[4:7]; ids=bean[7:10]; bs=bean[11:14]
# Option A: points are (xs[k], bs[k]) -> interpolate
ptsA=list(zip(xs,bs))
print("I over (xs,bs):", I(ptsA,m))
# Option B: the actual M output if coffee known... we dont know coffee
# Maybe the 'secret' = I over (ids, bs)? 
print("I over (ids,bs):", I(list(zip(ids,bs)),m))
# bean indices 0..3 small:11,big,27,big -> maybe (11,big),(27,big)
print("bean:",bean)
# pairs (bean[0],bean[1]),(bean[2],bean[3]) plus xs/bs
pts2=[(bean[0],bean[1]),(bean[2],bean[3])]+list(zip(xs[: ],bs[:]))
print("I mixed:", I(pts2,m))
