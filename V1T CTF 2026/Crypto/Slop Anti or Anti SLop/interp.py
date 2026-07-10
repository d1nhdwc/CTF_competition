from fractions import Fraction
from decimal import Decimal
import re
z = open("output.txt", encoding="utf-8").read()
pts = [(Fraction(x), Fraction(y)) for x, y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
n = len(pts)
# Solve for coeffs c0..c_{n-1} where P(x)=sum c_i x^i (P uses coffee in that order)
# Build Vandermonde and solve with Fractions via Gaussian elimination
A=[[p[0]**j for j in range(n)] for p in pts]
b=[p[1] for p in pts]
# gaussian
M=[row[:]+[b[i]] for i,row in enumerate(A)]
for col in range(n):
    piv=next(r for r in range(col,n) if M[r][col]!=0)
    M[col],M[piv]=M[piv],M[col]
    pv=M[col][col]
    M[col]=[v/pv for v in M[col]]
    for r in range(n):
        if r!=col and M[r][col]!=0:
            f=M[r][col]
            M[r]=[a-f*bb for a,bb in zip(M[r],M[col])]
coeffs=[M[i][n] for i in range(n)]
print("coeffs:")
for c in coeffs:
    print(c, "=>", float(c))
