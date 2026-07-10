leak1 = [123, 38, 92, 78, 207, 178, 116, 75, 141, 163]
leak2 = [4226, 36575, 42265, 42988, 32134, 53660, 36202, 48971, 61905, 20150, 45745]
leak3 = [10, 18, 13, 17, 17, 19, 14, 13, 18, 16, 15]
cipher = bytes.fromhex("72901442adade9c53b7cb386eeb8b6765d42dbc58ec6d442e77057b7d5d2724afc2f4e232df02f9ff050")

def pc(x): return bin(x).count("1")

# candidates[i] = list of words consistent with leak2[i] and leak3[i]
cands = []
for i in range(11):
    cs = []
    for lo in range(1 << 16):
        hi = leak2[i] ^ ((lo * 0x45d9f3b) & 0xFFFF)
        w = (hi << 16) | lo
        if pc(w) == leak3[i]:
            cs.append(w)
    cands.append(cs)

print([len(c) for c in cands])

# Use leak1 to chain: leak1[i] = ((w[i]^w[i+1])*0x9e3779b1 >> 24) & 0xFF
# DP over chain
def link_ok(a, b, i):
    return (((a ^ b) * 0x9e3779b1 >> 24) & 0xFF) == leak1[i]

# build viable sets via forward filtering
import itertools
# index by quick lookup
solutions = []
# beam: list of (word_value,) chains
chains = [[w] for w in cands[0]]
for i in range(1, 11):
    nxt = []
    for ch in chains:
        a = ch[-1]
        for b in cands[i]:
            if link_ok(a, b, i - 1):
                nxt.append(ch + [b])
    chains = nxt
    print("after", i, "chains:", len(chains))

print("total chains:", len(chains))

def words_to_bytes(words):
    return b"".join(w.to_bytes(4, "big") for w in words)[:len(cipher)]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

for ch in chains[:50]:
    ks = words_to_bytes(ch)
    flag = xor(cipher, ks)
    if flag.startswith(b"V1T{") or flag.startswith(b"v1t{"):
        print("FLAG:", flag)
