import re, base64
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c"))
print("cup len",len(cup))
print("nonce(y)=",cup[:12].hex())
ct=cup[12:]
print("ct+tag len", len(ct), "=> plaintext len", len(ct)-16)
