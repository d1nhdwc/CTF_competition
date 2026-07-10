import re, base64, hashlib
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
cup=base64.b64decode(q("c"))
y_target=cup[:12]
def H(x): return hashlib.sha256(x).digest()
def ydrip(coffee, cream):
    x=",".join(map(str,coffee)).encode()
    return hashlib.sha256(b"drip"+H(x)+b"cream"+H(str(cream).encode())).digest()[:12]
print("y_target", y_target.hex())
bean=[int(x) for x in q("v").split(",")]
foam=int(q("m"))
blend=[bean[0],bean[2],5,len(cup),foam.bit_length()]
# candidate coffee lists
coffees={
 "blend":blend,
 "bean":bean,
 "bean0_2":[bean[0],bean[2]],
}
# candidate creams: try many dump values
creams={
 "r":int(q("r")),"z":int(q("z")),"m":int(q("m")),"n":int(q("n")),
 "d":int(q("d")),"l":int(q("l")),
 "coffee_field":q("coffee"),"sugar_field":q("sugar"),"otp":q("otp"),
}
for cn,cf in coffees.items():
    for rn,cr in creams.items():
        if ydrip(cf,cr)==y_target:
            print("MATCH coffee=",cn,"cream=",rn)
print("done scan1")
