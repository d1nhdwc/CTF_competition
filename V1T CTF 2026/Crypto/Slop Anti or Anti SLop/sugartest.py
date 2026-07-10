import re, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
A=b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"
cup=base64.b64decode(q("c")); nonce=cup[:12]; ct=cup[12:]
def H(x): return hashlib.sha256(x).digest()
sugar=int(q("r"))  # per main, sugar = r
def Kfn(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"coffee"+H(x)+b"cream"+H(str(cream).encode())+b"sugar"+H(str(sugar).encode())).digest()
def trydec(coffee,cream):
    try:
        return AESGCM(Kfn(coffee,cream)).decrypt(nonce,ct,A)
    except Exception:
        return None
bean=[int(x) for x in q("v").split(",")]
foam=int(q("m")); n=int(q("n")); zz=int(q("z"))
# coffee = bean (v) ? cream = foam(m)? try matrix
coffee_cands={"bean":bean,"bean3":bean[:3],"b0b2":[bean[0],bean[2]]}
cream_cands={"m":foam,"n":n,"z":zz,"coffee_field":q("coffee"),"sugar_field":q("sugar")}
for cfn,cf in coffee_cands.items():
    for crn,cr in cream_cands.items():
        r=trydec(cf,cr)
        if r: print("FLAG", cfn,crn,r)
print("done; sugar=r assumption")
