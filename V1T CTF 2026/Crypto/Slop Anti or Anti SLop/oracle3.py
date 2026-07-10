import re, base64, hashlib, itertools
z=open("output.txt",encoding="utf-8").read()
def q(x): 
    mm=re.search(rf"^{x} = (.+)$", z, re.M)
    return mm.group(1).strip() if mm else None
cup=base64.b64decode(q("c"))
nonce=cup[:12]
def H(x): return hashlib.sha256(x).digest()
def ydrip(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]
# string field values
vals={k:q(k) for k in ["coffee","sugar","cmd","otp","h","a","d","l"]}
vals2={k:int(q(k)) for k in ["m","r","z","n","d","l"]}
allcream=list(vals.values())+list(vals2.values())+[None]
# coffee as single-element string list of each field, plus pairs
single_coffees=[[v] for v in vals.values()]+[ [v] for v in vals2.values()]
# also coffee as the literal word arabica etc, list-form ["arabica"]
print("nonce", nonce.hex())
for cf in single_coffees:
    for cr in allcream:
        if ydrip(cf,cr)==nonce:
            print("MATCH",cf,cr)
print("done")
