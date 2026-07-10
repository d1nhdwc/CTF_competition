import re, base64, hashlib
from decimal import Decimal

z = open("output.txt", encoding="utf-8").read()

def q(*p):
    for x in p:
        y = re.search(rf"^{x} = (.+)$", z, re.M)
        if y:
            return y.group(1).strip()
    raise SystemExit(7)

cup = base64.b64decode(q("c"))
bean = [int(x) for x in q("v").split(",")]
roast_raw = re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)
roast = [(Decimal(x), Decimal(y)) for x, y in roast_raw]
foam = int(q("m"))
sugar_r = int(q("r"))
pour = int(q("z"))
kettle = int(q("n"))
m = foam  # m field
m_field = int(q("m"))

def H(x):
    return hashlib.sha256(x).digest()

blend = [bean[0], bean[2], len(roast), len(cup), foam.bit_length()]
target = bytes.fromhex("d23f0a4a41c9d1e0e580a464")

# Precompute coffee hash for the confident coffee = blend list
coffee = blend
coffee_str = ",".join(map(str, coffee)).encode()
prefix = b"drip" + H(coffee_str) + b"cream"

def nonce_with_cream_str(cream_repr_bytes):
    return hashlib.sha256(prefix + H(cream_repr_bytes)).digest()[:12]

def test_cream(cream):
    return hashlib.sha256(prefix + H(str(cream).encode())).digest()[:12] == target

# M function
def M(coffee_, v, mm):
    a = v[10]; xs = v[4:7]; ids = v[7:10]; bs = v[11:14]
    return [(x, (a * coffee_[i] + y) % mm) for x, i, y in zip(xs, ids, bs)]

# I function
def I(v, mm):
    s = 0
    for i,(x,y) in enumerate(v):
        a=1;b=1
        for j,(u,_) in enumerate(v):
            if i==j: continue
            a=(a*(-u))%mm; b=(b*(x-u))%mm
        s=(s+y*a*pow(b,-1,mm))%mm
    return s

cands = []
def add(c): cands.append(c)

# integers from file
for v in [foam, sugar_r, pour, kettle, m_field] + bean:
    add(v)
# small ints
for v in range(0, 300):
    add(v)
# negative small
for v in range(-50, 0):
    add(v)
# M output forms
try:
    Mout = M(coffee, bean, m_field)
    add(Mout); add(str(Mout))
    add(I([(Decimal(a),Decimal(b)) for a,b in Mout], m_field) if False else None)
except Exception as e:
    print("M err", e)
# I over roast points reduced mod m (x as int? unlikely) skip
# strings
for s in ["arabica","cube","milk","none","None","coffee","cream","sugar","v1t",
          q("h") if re.search(r"^h = ",z,re.M) else "", q("otp") if re.search(r"^otp = ",z,re.M) else "",
          q("cmd") if re.search(r"^cmd = ",z,re.M) else ""]:
    add(s)
# blend forms as cream
add(blend); add(str(blend)); add(":".join(map(str,blend)))
add(bean); add(str(bean))
add(coffee_str.decode())

found=False
for c in cands:
    try:
        if test_cream(c):
            print("CREAM MATCH:", repr(c))
            found=True
    except Exception:
        pass
print("done sweep, found=", found, "tested", len(cands))
