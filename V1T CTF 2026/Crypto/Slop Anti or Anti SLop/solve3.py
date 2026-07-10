import re, base64, hashlib
from decimal import Decimal

z = open("output.txt", encoding="utf-8").read()
def q(*p):
    for x in p:
        y = re.search(rf"^{x} = (.+)$", z, re.M)
        if y: return y.group(1).strip()
    raise SystemExit(7)

cup = base64.b64decode(q("c"))
bean = [int(x) for x in q("v").split(",")]
roast = re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)
foam = int(q("m")); sugar_r = int(q("r")); pour = int(q("z")); kettle = int(q("n"))
m_field = foam
def H(x): return hashlib.sha256(x).digest()
target = bytes.fromhex("d23f0a4a41c9d1e0e580a464")
blend = [bean[0], bean[2], len(roast), len(cup), foam.bit_length()]

def M(coffee_, v, mm):
    a=v[10]; xs=v[4:7]; ids=v[7:10]; bs=v[11:14]
    return [(x,(a*coffee_[i]+y)%mm) for x,i,y in zip(xs,ids,bs)]

# Build coffee candidates
coffee_cands = {
    "blend": blend,
    "bean": bean,
    "blend_colon_chars": [11,27,5,113,89],
}
# M needs coffee idx up to 7 -> only bean works
try:
    coffee_cands["M_bean"] = M(bean, bean, m_field)
except Exception as e:
    print("Mbean err", e)

# Cream candidates (str() reproducible)
creams = []
for v in [foam, sugar_r, pour, kettle, m_field]: creams.append(v)
creams += bean
creams += list(range(-5, 1000))
creams += [str(foam), str(sugar_r), str(pour), str(kettle)]
creams += [None, True, False]
creams += [blend, bean, ":".join(map(str,blend)), str(blend), str(bean)]
# hash-derived
aroma = hashlib.sha256(b"|".join([H(cup), H(",".join(map(str,bean)).encode()),
        H(str(sugar_r^pour^kettle.bit_length()).encode())])).hexdigest()
creams += [aroma, aroma[:32], int(aroma[:32],16), int(aroma,16)]
# field decoys
for f in ["d","l","h","otp","cmd"]:
    if re.search(rf"^{f} = ",z,re.M): creams.append(q(f))
creams += ["arabica","cube"]

found=False
for cn, coffee in coffee_cands.items():
    cs = ",".join(map(str,coffee)).encode()
    prefix = b"drip"+H(cs)+b"cream"
    for cr in creams:
        try:
            if hashlib.sha256(prefix+H(str(cr).encode())).digest()[:12]==target:
                print(f"MATCH coffee={cn} cream={cr!r}")
                found=True
        except Exception: pass
print("found=",found)
