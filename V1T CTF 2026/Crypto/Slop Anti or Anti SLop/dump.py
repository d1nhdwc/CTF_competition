import re
z=open("output.txt",encoding="utf-8").read()
def q(x):
    return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
bean=[int(x) for x in q("v").split(",")]
print("bean(v) =",bean)
print("len bean",len(bean))
print("n bitlen", int(q("n")).bit_length())
print("r =", int(q("r")), "bitlen", int(q("r")).bit_length())
print("z =", int(q("z")))
print("m =", int(q("m")), "bitlen", int(q("m")).bit_length())
print("d =", q("d"),"l =",q("l"),"h=",q("h"))
print("otp =", q("otp"))
print("coffee field =", q("coffee"))
print("sugar field =", q("sugar"))
print("cmd =", q("cmd"))
