import re, hashlib, base64
z = open("output.txt", encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
sugar_r = int(q("r")); pour = int(q("z")); kettle = int(q("n")); foam = int(q("m"))
cup = base64.b64decode(q("c")); bean = [int(t) for t in q("v").split(",")]
def H(x): return hashlib.sha256(x).digest()
xorval = sugar_r ^ pour ^ kettle.bit_length()
aroma = hashlib.sha256(b"|".join([H(cup), H(",".join(map(str,bean)).encode()), H(str(xorval).encode())])).hexdigest()
print("aroma32 =", aroma[:32])
print("xorval =", xorval)
print("n.bit_length =", kettle.bit_length())
print("r.bit_length =", sugar_r.bit_length())

# Check: does the printed 'sugar' (aroma[:32]) actually serve as the AES sugar param?
# In E/K, sugar is hashed via H(str(sugar)). The dump's printed sugar = aroma[:32] (a hex string).
# Hypothesis: sugar passed to E = aroma[:32] string  OR  int(aroma[:32],16)
print("sugar candidate (hexstr):", aroma[:32])
print("sugar candidate (int):", int(aroma[:32],16))
