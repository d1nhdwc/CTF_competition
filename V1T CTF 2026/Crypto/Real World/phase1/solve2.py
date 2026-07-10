import csv, re, random
from pathlib import Path
import numpy as np

HERE = Path(__file__).parent
Q = 1048583
N = 12

Adict = {}
for row in csv.DictReader(open(HERE / "a_vectors.csv")):
    i = int(row["i"]); Adict[i] = [int(row[f"a{j}"]) % Q for j in range(N)]

Ydict = {}; flagged = set(); hexlen = {}
pat = re.compile(r"^\*?\s*(\d+)[\.,:]?\s*Y\s*=\s*([0-9A-Fa-f]+)")
for line in (HERE / "solve_frame.txt").read_text().splitlines():
    s = line.strip(); m = pat.match(s)
    if not m: continue
    idx = int(m.group(1)); h = m.group(2)
    Ydict[idx] = int(h, 16) % Q; hexlen[idx] = len(h)
    if "*" in s: flagged.add(idx)

# "clean" = 5 hex digits, not flagged
idxs = sorted(set(Adict) & set(Ydict))
A = np.array([Adict[i] for i in idxs], dtype=np.int64)
Y = np.array([Ydict[i] for i in idxs], dtype=np.int64)
clean = [k for k, i in enumerate(idxs) if i not in flagged and hexlen[i] == 5]
print(f"M={len(idxs)} clean(5digit,unflagged)={len(clean)}")

def inv(a): return pow(int(a) % Q, Q - 2, Q)
def solve_system(rows, bs):
    m = [[int(x) for x in r] + [int(b)] for r, b in zip(rows, bs)]
    for col in range(N):
        piv = next((r for r in range(col, N) if m[r][col] % Q), None)
        if piv is None: return None
        m[col], m[piv] = m[piv], m[col]
        ivp = inv(m[col][col]); m[col] = [(x * ivp) % Q for x in m[col]]
        for r in range(N):
            if r != col and m[r][col] % Q:
                f = m[r][col]; m[r] = [(x - f * y) % Q for x, y in zip(m[r], m[col])]
    return [m[r][N] % Q for r in range(N)]

def count_within(s, B):
    r = (Y - A.dot(s)) % Q
    r = np.where(r > Q // 2, r - Q, r)
    return int((np.abs(r) <= B).sum())

random.seed(2)
best = None; bs = -1
TRIALS = 60000
for t in range(TRIALS):
    pick = random.sample(clean, N)
    sol = solve_system(A[pick], Y[pick])
    if sol is None: continue
    s = np.array(sol, dtype=np.int64)
    sc = count_within(s, 300)   # small error bound
    if sc > bs:
        bs = sc; best = s
        print(f"t={t} score(B=300)={sc}/{len(idxs)}")
        if sc > 0.3 * len(idxs):
            break
print("best", bs, best.tolist() if best is not None else None)
if best is not None:
    r = (Y - A.dot(best)) % Q; r = np.where(r > Q // 2, r - Q, r)
    h, _ = np.histogram(np.abs(r), bins=[0,5,50,500,5000,50000,Q])
    print("hist", h)
    np.save(HERE / "secret.npy", best)
