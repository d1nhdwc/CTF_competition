import re, base64, hashlib, itertools
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
A=b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"
cup=base64.b64decode(q("c")); nonce=cup[:12]; ct=cup[12:]
def H(x): return hashlib.sha256(x).digest()
def Kfn(coffee,cream,sugar):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"coffee"+H(x)+b"cream"+H(str(cream).encode())+b"sugar"+H(str(sugar).encode())).digest()
def dec(coffee,cream,sugar):
    try: return AESGCM(Kfn(coffee,cream,sugar)).decrypt(nonce,ct,A)
    except: return None
coffee_print="11:27:5:113:89"
sugar_aroma="a6c474d9e2014567397094be60a5ea64"
# coffee forms
coffee_forms={
 "list":[11,27,5,113,89],
 "strlist":[coffee_print],
 "colon_chars":list(coffee_print),
}
vals=[coffee_print, sugar_aroma, q("coffee"),q("sugar"),q("otp"),q("h"),q("a"),q("cmd"),
      int(q("r")),int(q("z")),int(q("n")),int(q("m")),int(q("d")),int(q("l"))]
for cfn,cf in coffee_forms.items():
    for cr in vals:
        for sg in vals:
            r=dec(cf,cr,sg)
            if r: print("FLAG",cfn,repr(cr)[:20],repr(sg)[:20],r)
print("done printed-output brute")
