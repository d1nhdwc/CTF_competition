from fractions import Fraction
import re, sympy
z=open("output.txt",encoding="utf-8").read()
pts=[(Fraction(x),Fraction(y)) for x,y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
for i,(x,y) in enumerate(pts):
    print(i,"xden factors:", sympy.factorint(x.denominator))
