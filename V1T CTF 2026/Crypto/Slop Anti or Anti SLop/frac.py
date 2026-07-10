from fractions import Fraction
import re
z=open("output.txt",encoding="utf-8").read()
pts=[(Fraction(x),Fraction(y)) for x,y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
for x,y in pts:
    print("x num/den bitlen:", x.numerator.bit_length(), x.denominator.bit_length(), " den factor:")
    print("  xden", x.denominator)
    print("  yden", y.denominator, "ynum bitlen", abs(y.numerator).bit_length())
