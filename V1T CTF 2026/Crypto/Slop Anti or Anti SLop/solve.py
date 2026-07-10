import re, base64, hashlib

z = open("output.txt", encoding="utf-8").read()

def q(*p):
    for x in p:
        y = re.search(rf"^{x} = (.+)$", z, re.M)
        if y:
            return y.group(1).strip()
    raise SystemExit(7)

cup = base64.b64decode(q("c"))
bean = [int(x) for x in q("v").split(",")]
roast = re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)
foam = int(q("m"))
sugar_r = int(q("r"))
pour = int(q("z"))
kettle = int(q("n"))

def H(x):
    return hashlib.sha256(x).digest()

blend = [bean[0], bean[2], len(roast), len(cup), foam.bit_length()]  # [11,27,5,113,89]
aroma = hashlib.sha256(
    b"|".join([
        H(cup),
        H(",".join(map(str, bean)).encode()),
        H(str(sugar_r ^ pour ^ kettle.bit_length()).encode()),
    ])
).hexdigest()
aroma32 = aroma[:32]

target = bytes.fromhex("d23f0a4a41c9d1e0e580a464")

def nonce_of(coffee, cream):
    x = ",".join(map(str, coffee)).encode()
    return hashlib.sha256(b"drip" + H(x) + b"cream" + H(str(cream).encode())).digest()[:12]

# Build a big list of coffee candidates (different representations)
coffee_cands = {}
coffee_cands["blend_list"] = blend                          # [11,27,5,113,89]
coffee_cands["blend_colonstr"] = ":".join(map(str, blend))  # "11:27:5:113:89"
coffee_cands["blend_str"] = str(blend)
coffee_cands["bean"] = bean

# cream candidates - lots of forms
cream_cands = []
labels = {}
def add(label, val):
    cream_cands.append(val); labels[id(val)] = label

add("foam", foam)
add("sugar_r", sugar_r)
add("pour", pour)
add("kettle", kettle)
add("aroma32", aroma32)
add("aroma_full", aroma)
add("aroma32_int", int(aroma32, 16))
add("bean10", bean[10])
add("blend_colon", ":".join(map(str, blend)))
add("None", None)
add("int0", 0)
add("int1", 1)
# decoy fields
for f in ["d","l","h","otp"]:
    v = q(f) if re.search(rf"^{f} = ", z, re.M) else None
    if v is not None:
        add(f"field_{f}", v)
add("arabica", "arabica")
add("cube", "cube")
# xor value used in aroma
add("xor_val", sugar_r ^ pour ^ kettle.bit_length())
add("xor_val_str", str(sugar_r ^ pour ^ kettle.bit_length()))

found = False
for cname, coffee in coffee_cands.items():
    for cr in cream_cands:
        try:
            if nonce_of(coffee, cr) == target:
                print(f"MATCH coffee[{cname}]={coffee!r} cream[{labels[id(cr)]}]={cr!r}")
                found = True
        except Exception as e:
            pass
if not found:
    print("no match in sweep 2")
