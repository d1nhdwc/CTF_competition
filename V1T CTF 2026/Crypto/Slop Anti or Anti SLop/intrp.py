from decimal import Decimal, getcontext
import re
getcontext().prec=4000
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
roast=[(Decimal(x),Decimal(y)) for x,y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
# Solve for integer coeffs of degree D using first D+1 points, exact Decimal gaussian, then round, verify all.
def solve(D):
    pts=roast[:D+1]
    A=[[p[0]**j for j in range(D+1)] for p in pts]
    b=[p[1] for p in pts]
    M=[row[:]+[b[i]] for i,row in enumerate(A)]
    n=D+1
    for col in range(n):
        piv=next(r for r in range(col,n) if M[r][col]!=0)
        M[col],M[piv]=M[piv],M[col]
        pv=M[col][col]; M[col]=[v/pv for v in M[col]]
        for r in range(n):
            if r!=col and M[r][col]!=0:
                f=M[r][col]; M[r]=[a-f*bb for a,bb in zip(M[r],M[col])]
    coeffs=[M[i][n] for i in range(n)]
    return coeffs
for D in range(1,5):
    c=solve(D)
    rounded=[ (cc).to_integral_value() for cc in c]
    print("D=",D)
    for cc,rr in zip(c,rounded):
        print("   ", str(cc)[:40], "->", rr)
