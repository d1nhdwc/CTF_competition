#!/usr/bin/env python3
import ast
import math
import random
import re
import string
from collections import Counter

random.seed(0)

with open("logbook.txt", "r") as f:
    txt = f.read()

m = re.search(r"Log:\s*(\[[^\n]+\])\s*Ciphertext:\s*([0-9a-fA-F]+)", txt, re.S)
if not m:
    raise RuntimeError("bad logbook format")

xs = ast.literal_eval(m.group(1))
ct = bytes.fromhex(m.group(2))

# Step 1: recover modulus P
Ds = []
for i in range(len(xs) - 3):
    d1 = xs[i + 1] - xs[i]
    d2 = xs[i + 2] - xs[i + 1]
    d3 = xs[i + 3] - xs[i + 2]
    D = abs(d3 * d1 - d2 * d2)
    if D:
        Ds.append(D)

big_gcds = []
for _ in range(6000):
    i, j = random.sample(range(len(Ds)), 2)
    g = math.gcd(Ds[i], Ds[j])
    if g.bit_length() > 400:
        big_gcds.append(g)

P = 0
for g in big_gcds:
    P = math.gcd(P, g)

if P == 0:
    raise RuntimeError("failed to recover modulus")

print("[*] recovered P =", P)

# Step 2: recover affine heads
pairs = [(xs[i], xs[i + 1]) for i in range(len(xs) - 1)]

def line_from(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        return None
    a = ((y1 - y2) * pow((x1 - x2) % P, -1, P)) % P
    b = (y1 - a * x1) % P
    return (a, b)

def support(line, remaining_idx):
    a, b = line
    idx = []
    for i in remaining_idx:
        x, y = pairs[i]
        if (a * x + b - y) % P == 0:
            idx.append(i)
    return idx

remaining = set(range(len(pairs)))
heads = []

while remaining:
    best_line = None
    best_idx = []

    rem_list = list(remaining)
    for _ in range(5000):
        i, j = random.sample(rem_list, 2)
        line = line_from(pairs[i], pairs[j])
        if line is None:
            continue
        idx = support(line, remaining)
        if len(idx) > len(best_idx):
            best_line = line
            best_idx = idx

    if not best_line or not best_idx:
        raise RuntimeError("failed to recover heads")

    heads.append(best_line)
    for i in best_idx:
        remaining.remove(i)

print("[*] recovered", len(heads), "heads")

# Step 3: label the observed hidden-state sequence
state_seq = []
for x, y in pairs:
    hit = None
    for hid, (a, b) in enumerate(heads):
        if (a * x + b - y) % P == 0:
            hit = hid
            break
    if hit is None:
        raise RuntimeError("uncovered transition")
    state_seq.append(hit)

print("[*] state counts =", Counter(state_seq))

# Step 4: estimate empirical transition probabilities
N = len(heads)
counts = [[0] * N for _ in range(N)]
for s, t in zip(state_seq, state_seq[1:]):
    counts[s][t] += 1

row_sums = [sum(r) for r in counts]
probs = [
    [(counts[i][j] / row_sums[i]) if row_sums[i] else 0.0 for j in range(N)]
    for i in range(N)
]

# Step 5: search future state paths and decrypt
allowed_inner = set(string.ascii_letters + string.digits + "_")
results = []

def score_path(path):
    prev = state_seq[-1]
    s = math.log(probs[prev][path[0]] + 1e-300)
    for a, b in zip(path, path[1:]):
        s += math.log(probs[a][b] + 1e-300)
    return s

frontier = [(xs[-1], [], "")]
for i, c in enumerate(ct):
    new_frontier = []
    for xcur, path, msg in frontier:
        for sid, (a, b) in enumerate(heads):
            xn = (a * xcur + b) % P
            ch = chr(c ^ (xn & 0xFF))
            if i == 0 and ch != "R":
                continue
            if i == 1 and ch != "S":
                continue
            if i == 2 and ch != "{":
                continue
            if i == len(ct) - 1 and ch != "}":
                continue
            if 2 < i < len(ct) - 1 and ch not in allowed_inner:
                continue
            new_frontier.append((xn, path + [sid], msg + ch))

    frontier = new_frontier
    print(f"[*] depth {i:02d}: {len(frontier)} candidates")

for _, path, msg in frontier:
    if re.fullmatch(r"RS\{[A-Za-z0-9_]+\}", msg):
        results.append((score_path(path), msg, path))

results.sort(reverse=True)

if not results:
    raise RuntimeError("no flag candidates")

print("\nFLAG:", results[0][1])
