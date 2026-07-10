from decimal import Decimal, getcontext
import re
getcontext().prec = 2000
z = open("output.txt", encoding="utf-8").read()
roast = [(Decimal(x), Decimal(y)) for x, y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
for x,y in roast:
    print("x=",x)
    print("ylen=",len(str(y)))
print("npts", len(roast))
