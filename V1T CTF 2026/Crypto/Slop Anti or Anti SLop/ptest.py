from decimal import Decimal, getcontext
import re
getcontext().prec=3000
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
bean=[int(x) for x in q("v").split(",")]
roast=[(Decimal(x),Decimal(y)) for x,y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
def P(x,coffee):
    s=Decimal(0); t=Decimal(1)
    for v in coffee:
        s+=Decimal(v)*t; t*=x
    return s
# try bean as coffee
for i,(x,y) in enumerate(roast):
    val=P(x,bean)
    print(i,"diff",  (val-y))
