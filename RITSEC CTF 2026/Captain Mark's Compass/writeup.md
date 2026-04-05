# RITSEC Crypto Writeup — `navigate.py` + `logbook.txt`

## Challenge Summary

We are given two files:

- `navigate.py`, which implements the generator and the encryption routine.
- `logbook.txt`, which contains a long list of outputs from the generator and the final ciphertext.

The goal is to recover Pierre's hidden message and output the flag in the format `RS{...}`.

For the provided instance, the recovered flag is:

```text
RS{w04h_h1dd3n_M4rk0v_br34k5_LCGs}
```

---

## 1. What the source code tells us

The core logic in `navigate.py` is a state machine with two layers:

1. A **hidden discrete state** `curr`.
2. A **numeric state** `sval` updated by an affine map.

At every step, the generator does:

```python
(a, b) = heads[curr]
sval = (a * sval + b) % P
```

Then it transitions to the next hidden state according to a Markov transition matrix `PROBS`.

So this is **not** a single LCG. It is a **Markov-switched affine generator**: each hidden state selects a different affine recurrence.

The encryption routine is also simple:

```python
strm = [lcg.next() & 0xFF for _ in range(len(flag))]
ct = keystream XOR flag
```

That means if we can predict the future outputs of the generator after the log ends, we can recover the plaintext byte by byte.

---

## 2. Why the 850 logged outputs are enough

The file `logbook.txt` gives us 850 consecutive outputs before encryption starts.

That is extremely valuable because every consecutive pair `(x_n, x_{n+1})` must satisfy one of a small number of affine relations:

```text
a_i * x_n + b_i ≡ x_{n+1} (mod P)
```

Each pair lies on one of a few hidden lines over the finite field modulo `P`.

So the recovery problem becomes:

1. Recover the modulus `P`.
2. Recover the set of affine maps `(a_i, b_i)`.
3. Label each transition with its hidden state.
4. Use the learned transition behavior to extend the generator beyond the 850th value.
5. Decrypt the ciphertext.

---

## 3. Recovering the modulus `P`

If the same affine map is used for several steps in a row, then the sequence locally behaves like a standard affine recurrence:

```text
x_{n+1} = a x_n + b mod P
x_{n+2} = a x_{n+1} + b mod P
x_{n+3} = a x_{n+2} + b mod P
```

For such a run, the determinant-like quantity

```text
D_n = (x_{n+3}-x_{n+2})(x_{n+1}-x_n) - (x_{n+2}-x_{n+1})^2
```

must be divisible by `P`.

Because the generator sometimes stays in the same Markov state for consecutive steps, many of these `D_n` values are nonzero multiples of the true modulus.

So we can:

- compute many `D_n` values,
- take gcds of random pairs,
- then gcd those large results together.

That recovers the prime modulus `P`.

This step is the key observation that turns the problem from “unknown hybrid generator” into “finite-field line clustering”.

---

## 4. Recovering the affine heads `(a, b)`

Once `P` is known, every consecutive pair of outputs gives a constraint:

```text
y ≡ a x + b (mod P)
```

where `x = x_n` and `y = x_{n+1}`.

Because only a small number of hidden states exist, there are only a few distinct affine maps, and the full set of observed transitions is a union of a few lines modulo `P`.

A good way to recover them is a RANSAC-style approach:

1. Pick two observed pairs.
2. Solve for the unique line `(a, b)` through them modulo `P`.
3. Count how many transitions agree with that line.
4. Keep the best one.
5. Remove all transitions explained by that line.
6. Repeat until all transitions are covered.

After this step, we recover the full list of affine heads.

---

## 5. Recovering the hidden state sequence

Now every observed transition `(x_n, x_{n+1})` can be matched to exactly one recovered affine map.

So we can rewrite the numeric log as a sequence of hidden-state IDs such as:

```text
2, 2, 4, 1, 1, 1, 3, ...
```

This gives us an empirical estimate of the transition probabilities between states.

We do **not** actually need the original `tmatrix.txt`; the 850-step transcript lets us estimate the transition behavior directly from the observed state path.

That is enough for scoring candidate future paths.

---

## 6. Turning prediction into decryption

After the log ends, the same state machine continues running to generate the keystream for the flag.

We know:

- the final logged numeric value,
- the recovered affine maps,
- the approximate Markov transition behavior,
- the ciphertext bytes.

For each future character position, we can branch over every possible next hidden state:

1. apply that state's affine map,
2. compute the next numeric output,
3. take `output & 0xFF`,
4. XOR with the ciphertext byte,
5. check whether the resulting character is plausible.

This is where the flag format helps a lot.

We enforce:

- first bytes must be `R`, `S`, `{`,
- last byte must be `}`,
- middle bytes should be `[A-Za-z0-9_]`.

That pruning is extremely strong. Most branches die immediately.

Among the surviving candidates, we rank paths by the learned Markov transition likelihood. The best-scoring candidate is the real flag.

---

## 7. Why this attack works

The challenge tries to hide the generator behind two kinds of uncertainty:

- unknown modulus and affine maps,
- unknown switching between maps.

But the long transcript leaks enough structure to recover both.

The important lessons are:

- A Markov-switched generator still leaves algebraic fingerprints when it reuses the same mode several times in a row.
- Once the modulus is known, the transition graph becomes a clustering problem over affine maps.
- Even if future states are unknown, a flag-format constraint plus ciphertext validation can collapse the search space very quickly.

So the scheme fails because it combines several weak ideas without removing the correlations between consecutive outputs.

---

## 8. Solver outline

The practical solver follows this pipeline:

```text
parse logbook.txt
↓
compute determinant multiples and recover P with gcds
↓
recover all affine heads (a, b) by line clustering / RANSAC
↓
label each observed transition with a hidden state ID
↓
estimate state-transition probabilities
↓
search future state paths using ciphertext + flag charset pruning
↓
rank surviving candidates by path likelihood
↓
recover flag
```

---

## 9. Full solve script

Below is a compact solve script matching the approach above.

```python
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
```

---

## 10. Final Takeaway

The nice part of this challenge is that the generator looks complicated at first, but it leaks structure in multiple places:

- repeated use of the same affine map,
- finite-field line geometry in consecutive transitions,
- weak output truncation (`& 0xFF` only),
- and a predictable flag format.

Once those pieces are combined, the hidden state machine becomes recoverable enough to predict the keystream and read the message.

---
*_s1lv3r_Bull3t*