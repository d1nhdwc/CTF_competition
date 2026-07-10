import re, base64, hashlib, itertools
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c")); nonce=cup[:12]
def H(x): return hashlib.sha256(x).digest()
def ny(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]==nonce
# many coffee candidate lists
bean=[int(x) for x in q("v").split(",")]
ans="RSA_NoHashInHere_PoW_OTP"
coffee_cands=[]
coffee_cands.append(["arabica"])  # coffee field
coffee_cands.append(["arabica","cube"])
coffee_cands.append([q("coffee")])
coffee_cands.append([ans])
coffee_cands.append(list(ans))
coffee_cands.append([q("cmd")])
coffee_cands.append([q("a")])
# bean subsets
coffee_cands.append(bean)
coffee_cands.append(bean[:3])
coffee_cands.append([bean[0],bean[2]])
# cream small + fields
creams=list(range(0,200000))
fields=[q("coffee"),q("sugar"),q("otp"),q("h"),q("cmd"),q("a"),ans]
import sys
for cf in coffee_cands:
    for cr in fields:
        if ny(cf,cr): print("NONCE MATCH",cf,"cream=",cr); sys.exit()
    for cr in creams:
        if ny(cf,cr): print("NONCE MATCH",cf,"cream=",cr); sys.exit()
print("no match in this set")
