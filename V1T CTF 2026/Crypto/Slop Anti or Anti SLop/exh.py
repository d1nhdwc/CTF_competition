import re, hashlib, base64, sys, itertools
z=open("output.txt",encoding="utf-8").read()
def q(x): 
    mm=re.search(rf"^{x} = (.+)$", z, re.M); return mm.group(1).strip() if mm else None
cup_b64=q("c")
cup=base64.b64decode(cup_b64); nonce=cup[:12]
def H(x): return hashlib.sha256(x).digest()
def ny(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]==nonce
fields={k:q(k) for k in ["c","a","n","r","z","m","v","d","l","h","otp","coffee","sugar","cmd"]}
# build coffee candidate single-values (string forms)
strvals=list(fields.values())
# numeric forms
for k in ["n","r","z","m","d","l"]:
    strvals.append(int(fields[k]))
bean=[int(x) for x in fields["v"].split(",")]
# coffee candidates
coffee_cands=[]
for v in strvals: coffee_cands.append([v])
coffee_cands.append(bean)
for i in range(len(bean)): coffee_cands.append(bean[:i+1])
coffee_cands.append([bean[0],bean[2]])
# cream candidates: all strvals + ints
cream_cands=list(strvals)+list(range(0,2000))
print("coffee cands",len(coffee_cands),"cream cands",len(cream_cands))
for cf in coffee_cands:
    for cr in cream_cands:
        if ny(cf,cr):
            print("NONCE MATCH coffee=",cf,"cream=",cr); sys.exit()
print("no match exhaustive-1")
