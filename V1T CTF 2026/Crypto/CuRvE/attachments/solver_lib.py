"""Core math for the CURVE attack: weak-curve search + Pohlig-Hellman + CRT.

Strategy:
  change_parameters() reuses the SAME private key d on a curve we control over a
  server-chosen 256-bit prime p, then publishes G and Q = d*G plus the curve order n.
  The only guard is "n has at least one prime factor > 2^60", which does NOT prevent
  the rest of n from being smooth. We pick (a,b) so that n = (smooth small primes) * q
  with q a single big prime (so the server's factor(n) is fast and the guard passes).
  Pohlig-Hellman recovers d mod (smooth part); CRT across several curves recovers full d.
"""
import cypari2
import random
from multiprocessing import Pool

# --- per-worker Pari instance ---
_pari = None


def _winit():
    global _pari
    _pari = cypari2.Pari()
    _pari.allocatemem(1 << 29)


def _attempt(args):
    p, a, bound, big_min, smooth_thresh, seed = args
    pari = _pari
    rnd = random.Random(seed)
    b = rnd.randrange(1 << 101, 1 << 200)
    try:
        E = pari.ellinit([a, b], p)
        if E == 0:
            return None
        n = int(pari.ellcard(E))
    except Exception:
        return None
    try:
        f = pari.factor(n, bound)
    except Exception:
        return None
    smooth = 1
    cof = 1
    for i in range(len(f[0])):
        q = int(f[0][i]); e = int(f[1][i])
        if q < bound:
            smooth *= q ** e
        else:
            cof *= q ** e
    if cof > big_min and bool(pari.ispseudoprime(cof)) and smooth.bit_length() >= smooth_thresh:
        return (b, n, smooth.bit_length())
    return None


def find_curve(p, a, bound, big_min, smooth_thresh, nproc=12, max_batches=400):
    """Search random b until a curve over GF(p) with E=[a,b] has order =
    (smooth part >= smooth_thresh bits) * (single prime > big_min)."""
    seed = random.randrange(1 << 60)
    with Pool(nproc, initializer=_winit) as pool:
        for batch in range(max_batches):
            args = [(p, a, bound, big_min, smooth_thresh, seed + batch * nproc + i)
                    for i in range(nproc)]
            best = None
            for r in pool.map(_attempt, args):
                if r is not None and (best is None or r[2] > best[2]):
                    best = r
            if best is not None:
                pool.terminate()
                return best  # (b, n, smooth_bits)
    raise RuntimeError("no curve found")


# --- Pohlig-Hellman on one curve (main-process Pari) ---
def pohlig_hellman(pari, p, a, b, n, Gxy, Qxy, bound):
    """Return dict {prime: (exp, residue)} giving d mod prime^exp for each small prime."""
    E = pari.ellinit([a, b], p)
    G = pari([Gxy[0], Gxy[1]])
    Q = pari([Qxy[0], Qxy[1]])
    f = pari.factor(n, bound)
    out = {}
    for i in range(len(f[0])):
        q = int(f[0][i]); e = int(f[1][i])
        if q >= bound:
            continue
        pe = q ** e
        cof = n // pe
        Gp = pari.ellmul(E, G, cof)
        if Gp == pari([0]) or (len(Gp) == 1):
            continue
        m = int(pari.ellorder(E, Gp))   # = q^f, f<=e
        if m == 1:
            continue
        Qp = pari.ellmul(E, Q, cof)
        x = int(pari.elllog(E, Qp, Gp, m))
        # m = q^f
        out[q] = (m.bit_length(), x, m)
    return out


def crt(pairs):
    """pairs: list of (residue, modulus). Returns (x, M)."""
    x = 0
    M = 1
    for r, m in pairs:
        # combine x mod M with r mod m (assume coprime-enough; primes distinct powers)
        g = _egcd(M, m)
        # general CRT
        x = _crt2(x, M, r % m, m)
        M = M // _gcd(M, m) * m
    return x % M, M


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = _egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def _crt2(r1, m1, r2, m2):
    g, p1, p2 = _egcd(m1, m2)
    if (r2 - r1) % g != 0:
        raise ValueError("CRT inconsistent")
    lcm = m1 // g * m2
    tmp = (r1 + (r2 - r1) // g * p1 % (m2 // g) * m1) % lcm
    return tmp
