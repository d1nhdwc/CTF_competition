import re, hashlib, itertools, string
z=open("output.txt",encoding="utf-8").read()
def q(x): return re.search(rf"^{x} = (.+)$", z, re.M).group(1).strip()
target="7cdb52081db7eade46435eeef8879f1f67602b92"
def s1(b): return hashlib.sha1(b).hexdigest()
# test many candidate inputs
cands=[]
for k in ["coffee","sugar","otp","a","cmd"]:
    cands.append(q(k))
for k in ["m","r","z","n","d","l"]:
    cands.append(q(k))
cands+= ["RSA_NoHashInHere_PoW_OTP","arabica","cube","11:27:5:113:89","r1muru"]
for c in cands:
    if s1(c.encode())==target: print("SHA1 MATCH:",c)
# l=5 might mean length 5, d=8 difficulty. brute lowercase len up to 5
print("brute len<=5 lowercase...")
alph=string.ascii_lowercase+string.digits
found=False
for L in range(1,6):
    for t in itertools.product(alph,repeat=L):
        s="".join(t)
        if hashlib.sha1(s.encode()).hexdigest()==target:
            print("FOUND PREIMAGE:",s); found=True; break
    if found: break
if not found: print("no short preimage")
