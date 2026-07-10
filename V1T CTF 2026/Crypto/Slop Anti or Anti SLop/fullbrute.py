import re, base64, hashlib, itertools
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
z=open("output.txt",encoding="utf-8").read()
def q(x):
    mm=re.search(rf"^{x} = (.+)$", z, re.M); return mm.group(1).strip() if mm else None
A=b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"
cup=base64.b64decode(q("c")); nonce=cup[:12]; ct=cup[12:]
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
sugar_r=int(q("r")); pour=int(q("z")); kettle=int(q("n"))
aroma=hashlib.sha256(b"|".join([H(cup),H(",".join(map(str,bean)).encode()),H(str(sugar_r^pour^kettle.bit_length()).encode())])).hexdigest()
coffee_print="%d:%d:%d:%d:%d"%tuple(blend)
# coffee candidates (as lists, since K joins by comma)
coffee_cands={
 "blend":blend,
 "blend_colon_list":[coffee_print],
 "bean":bean,
}
scalar_cands={
 "aroma":aroma,"aroma32":aroma[:32],"coffee_print":coffee_print,
 "r":sugar_r,"z":pour,"n":kettle,"m":foam,
 "coffee_field":q("coffee"),"sugar_field":q("sugar"),"otp":q("otp"),
 "h":q("h"),"d":int(q("d")),"l":int(q("l")),"cmd":q("cmd"),
}
print("trying full tag oracle over product...")
found=False
for cfn,cf in coffee_cands.items():
    for crn,cr in scalar_cands.items():
        for sgn,sg in scalar_cands.items():
            try:
                pt=AESGCM(Kfn(cf,cr,sg)).decrypt(nonce,ct,A)
                print("FLAG FOUND", cfn,crn,sgn, pt); found=True
            except Exception:
                pass
print("found",found)
