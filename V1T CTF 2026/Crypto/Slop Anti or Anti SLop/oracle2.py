import re, base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
A=b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"
cup=base64.b64decode(q("c"))
nonce=cup[:12]; ct=cup[12:]
def H(x): return hashlib.sha256(x).digest()
def Kfn(coffee,cream,sugar):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"coffee"+H(x)+b"cream"+H(str(cream).encode())+b"sugar"+H(str(sugar).encode())).digest()
def ydrip(coffee,cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]
bean=[int(x) for x in q("v").split(",")]
foam=int(q("m"))
blend=[bean[0],bean[2],5,len(cup),foam.bit_length()]
# recompute aroma like main
sugar_r=int(q("r")); pour=int(q("z")); kettle=int(q("n"))
aroma=hashlib.sha256(b"|".join([H(cup),H(",".join(map(str,bean)).encode()),H(str(sugar_r^pour^kettle.bit_length()).encode())])).hexdigest()
# coffee candidates as lists
coffee_cands={
 "blend":blend,
 "blend_str":["%d:%d:%d:%d:%d"%tuple(blend)],  # if passed as single string list
 "bean":bean,
}
cream_cands={"r":sugar_r,"z":pour,"n":kettle,"m":foam,"aroma":aroma,"aroma32":aroma[:32],
 "coffee_field":q("coffee"),"sugar_field":q("sugar"),"otp":q("otp"),"d":int(q("d")),"l":int(q("l"))}
# first find coffee+cream via nonce oracle
print("nonce target", nonce.hex())
for cn,cf in coffee_cands.items():
    for crn,cr in cream_cands.items():
        if ydrip(cf,cr)==nonce:
            print("NONCE MATCH coffee=",cn,"cream=",crn)
print("scan done")
