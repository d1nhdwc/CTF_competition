import csv, re, random
from pathlib import Path
import numpy as np

HERE = Path(__file__).parent
Q = 1048583
N = 12

# --- parse a vectors ---
Adict = {}
with open(HERE / "a_vectors.csv") as f:
    for row in csv.DictReader(f):
        i = int(row["i"])
        Adict[i] = [int(row[f"a{j}"]) % Q for j in range(N)]

# --- parse Y values (hex) ---
Ydict = {}
flagged = set()
pat = re.compile(r"^\*?\s*(\d+)[\.,:]?\s*Y\s*=\s*([0-9A-Fa-f]+)")
for line in (HERE / "solve_frame.txt").read_text().splitlines():
    s = line.strip()
    m = pat.match(s)
    if not m:
        continue
    idx = int(m.group(1))
    Ydict[idx] = int(m.group(2), 16) % Q
    if "*" in s:
        flagged.add(idx)

idxs = sorted(set(Adict) & set(Ydict))
A = np.array([Adict[i] for i in idxs], dtype=np.int64)      # (M,N)
Y = np.array([Ydict[i] for i in idxs], dtype=np.int64)      # (M,)
flag_mask = np.array([i in flagged for i in idxs])
M = len(idxs)
print(f"samples M={M} flagged={flag_mask.sum()}")

def inv(a):
    return pow(int(a) % Q, Q - 2, Q)

def solve_system(rows, bs):
    m = [list(int(x) for x in r) + [int(b)] for r, b in zip(rows, bs)]
    n = N
    for col in range(n):
        piv = next((r for r in range(col, n) if m[r][col] % Q != 0), None)
        if piv is None:
            return None
        m[col], m[piv] = m[piv], m[col]
        ivp = inv(m[col][col])
        m[col] = [(x * ivp) % Q for x in m[col]]
        for r in range(n):
            if r != col and m[r][col] % Q != 0:
                f = m[r][col]
                m[r] = [(x - f * y) % Q for x, y in zip(m[r], m[col])]
    return [m[r][n] % Q for r in range(n)]

def score(s, max_err=64):
    pred = (A.dot(np.array(s, dtype=object)) % Q)  # exact big-int via object to avoid overflow
    r = (Y - pred.astype(np.int64)) % Q
    r = np.where(r > Q // 2, r - Q, r)
    return int((np.abs(r) <= max_err).sum())

# A.dot with int64: max entry ~Q*Q*N ~ 1.3e18 < 9.2e18 int64 max -> safe
def score_fast(s):
    pred = (A.dot(s)) % Q
    r = (Y - pred) % Q
    r = np.where(r > Q // 2, r - Q, r)
    return int((np.abs(r) <= 64).sum()), r

def count_within(s, B):
    pred = (A.dot(s)) % Q
    r = (Y - pred) % Q
    r = np.where(r > Q // 2, r - Q, r)
    return int((np.abs(r) <= B).sum()), r

clean = [k for k in range(M) if not flag_mask[k]]
random.seed(1)
# wide tolerance B so the true secret stands out even with nonzero error
B = 2000
best = None; best_score = -1
for trial in range(20000):
    pick = random.sample(clean, N)
    sol = solve_system(A[pick], Y[pick])
    if sol is None:
        continue
    s = np.array(sol, dtype=np.int64)
    sc, _ = count_within(s, B)
    if sc > best_score:
        best_score = sc; best = s
        print(f"trial {trial}: score {sc}/{M}")
        if sc > 0.5 * M:
            break

sc, r = count_within(best, B)
print("best score(B=%d):" % B, sc, "/", M)
print("secret s =", best.tolist())
from collections import Counter
c = Counter(int(x) for x in r if abs(int(x)) <= 16)
print("small err dist:", sorted(c.items())[:40])
np.save(HERE / "secret.npy", best)
