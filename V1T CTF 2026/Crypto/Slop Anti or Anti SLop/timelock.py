import re,time
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
r=int(q("r")); n=int(q("n")); zz=int(q("z"))
t=time.time()
s=r
for i in range(zz):
    s=(s*s)%n
    if i%5000000==0:
        print("progress",i, time.time()-t,"s",flush=True)
print("R_RESULT =", s, flush=True)
open("timelock.txt","w").write(str(s))
print("done in",time.time()-t,"s")
