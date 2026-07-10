import re
from math import gcd
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
n=int(q("n")); r=int(q("r")); m=int(q("m"))
print("n % r ==0?", n% r==0)
print("gcd(n,r)=", gcd(n,r))
# is r prime?
import sympy
print("r prime?", sympy.isprime(r))
print("m prime?", sympy.isprime(m))
print("n/r if divides:", n//r if n%r==0 else "no")
# maybe n = r * s
print("n bitlen", n.bit_length(), "r bitlen", r.bit_length())
