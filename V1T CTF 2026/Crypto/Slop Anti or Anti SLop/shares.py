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
print("bean:",bean)
# pairs reading
print("I[(11,B1),(27,B3)] =", I([(bean[0],bean[1]),(bean[2],bean[3])],m))
# maybe shares are (44,c0),(58,c1),(73,c2) using xs and bs
print("I[(44,c0),(58,c1),(73,c2)] =", I(list(zip(bean[4:7],bean[11:14])),m))
# maybe (6,c0),(1,c1),(7,c2) ids,bs
print("I[(6,c0),(1,c1),(7,c2)] =", I(list(zip(bean[7:10],bean[11:14])),m))
# value at 0 = secret
