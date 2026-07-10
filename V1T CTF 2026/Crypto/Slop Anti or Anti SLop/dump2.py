import re
z=open("output.txt",encoding="utf-8").read()
def q(x):
    return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
m=int(q("m"))
bean=[int(x) for x in q("v").split(",")]
a=bean[10]; xs=bean[4:7]; ids=bean[7:10]; bs=bean[11:14]
print("M inputs: a=",a)
print("xs",xs,"ids",ids,"bs",bs)
# These points are (x, a*coffee[i]+b mod m). We don't know coffee yet.
# bean small ones: bean[0]=11 bean[2]=27 used in blend (len(roast)=5, len(cup), foam.bitlen)
import base64
cup=base64.b64decode(q("c"))
foam=int(q("m"))
blend=[bean[0],bean[2],5,len(cup),foam.bit_length()]
print("blend(coffee in main print) =", blend)
print("len(cup)=",len(cup))
