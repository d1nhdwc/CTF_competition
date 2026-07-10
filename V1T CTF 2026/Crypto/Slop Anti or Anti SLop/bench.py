import re,time
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
r=int(q("r")); n=int(q("n")); zz=int(q("z"))
t=time.time()
s=r
for i in range(100000):
    s=(s*s)%n
print("100k squarings took",time.time()-t,"s -> est full:", (time.time()-t)*zz/100000/60,"min")
