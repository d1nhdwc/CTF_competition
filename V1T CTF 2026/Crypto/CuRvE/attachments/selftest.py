"""End-to-end self-test of the math, using a LOCAL simulated server.

Verifies: weak-curve search, Pohlig-Hellman dlog, CRT recovery of a 21-letter
private key, and ECDSA signing that passes the challenge's exact verify logic.
"""
import cypari2, random, sys
from hashlib import sha256

pari = cypari2.Pari()
pari.allocatemem(1 << 30)


# ---------- helpers ----------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def crt(residues):
    """residues: list of (r, m) with pairwise-coprime m. -> (x, M)."""
    x, M = 0, 1
    for r, m in residues:
        g, p1, p2 = egcd(M, m)
        assert g == 1, "moduli not coprime"
        lcm = M * m
        x = (x + M * ((r - x) * p1 % m)) % lcm
        M = lcm
    return x, M


def find_weak_b(p, a, bound, big_min, thresh, rnd):
    """Sequential (self-test) search for b s.t. E=[a,b]/GF(p) has order
    smooth(>=thresh bits) * prime(>big_min)."""
    while True:
        b = rnd.randrange(1 << 101, 1 << 200)
        try:
            E = pari.ellinit([a, b], p)
            if E == 0:
                continue
            n = int(pari.ellcard(E))
        except Exception:
            continue
        f = pari.factor(n, bound)
        smooth, cof = 1, 1
        for i in range(len(f[0])):
            q = int(f[0][i]); e = int(f[1][i])
            if q < bound:
                smooth *= q ** e
            else:
                cof *= q ** e
        if cof > big_min and bool(pari.ispseudoprime(cof)) and smooth.bit_length() >= thresh:
            return b, n


def pohlig(p, a, b, n, G, Q, bound):
    """Return dict {prime: (residue, modulus=prime^f)} for small primes."""
    E = pari.ellinit([a, b], p)
    Gv = pari(list(G))
    Qv = pari(list(Q))
    f = pari.factor(n, bound)
    out = {}
    for i in range(len(f[0])):
        q = int(f[0][i]); e = int(f[1][i])
        if q >= bound:
            continue
        pe = q ** e
        cof = n // pe
        Gp = pari.ellmul(E, Gv, cof)
        if len(Gp) < 2:           # identity [0]
            continue
        ordp = int(pari.ellorder(E, Gp))
        if ordp == 1:
            continue
        Qp = pari.ellmul(E, Qv, cof)
        try:
            x = int(pari.elllog(E, Qp, Gp, ordp))
        except Exception:
            continue
        out[q] = (x % ordp, ordp)
    return out


# ---------- local "server" ----------
class SimServer:
    def __init__(self, d):
        self.d = d

    def gen_params(self):
        from Crypto.Util.number import getPrime
        self.p = getPrime(256)
        return self.p

    def submit(self, a, b):
        p = self.p
        E = pari.ellinit([a, b], p)
        n = int(pari.ellcard(E))
        # mimic guard: some factor > 2^60
        f = pari.factor(n)
        assert any(int(f[0][i]) > (1 << 60) for i in range(len(f[0])))
        # random G via ellordinate
        G = None
        for _ in range(10000):
            x = random.randrange(0, p)
            ys = pari.ellordinate(E, x)
            if len(ys) >= 1:
                G = pari([x, ys[0]])
                break
        assert G is not None
        Q = pari.ellmul(E, G, self.d)
        self.E, self.n, self.G, self.Q, self.a, self.b = E, n, G, Q, a, b
        return (int(G[0]), int(G[1])), (int(Q[0]), int(Q[1])), n


def challenge_verify(p, a, b, n, Qxy, r, s, msg):
    """Reimplements ECDSA_Verify from chall.py with cypari2."""
    N = n
    if not (0 < r < N) or not (0 < s < N):
        return False
    h = int(sha256(msg).hexdigest(), 16)
    E = pari.ellinit([a, b], p)
    Q = pari(list(Qxy))
    RHS = pari.elladd(E, pari.ellmul(E, pari([h % N]) if False else _G(pari, p, a, b), h % N), pari.ellmul(E, Q, r % N))
    return RHS  # placeholder, replaced below


def _G(*a):  # unused
    pass


def main():
    # 21 lowercase letters -> int
    from Crypto.Util.number import bytes_to_long
    alpha = "abcdefghijklmnopqrstuvwxyz"
    rnd = random.Random(1234)
    key = ''.join(rnd.choice(alpha) for _ in range(21))
    d = bytes_to_long(key.encode())
    print("[selftest] secret key:", key, "d.bit_length =", d.bit_length(), flush=True)

    srv = SimServer(d)
    a = 0x10000000000000000000000000000abcdef0123  # >2^100
    bound = 1 << 24
    big_min = 1 << 60
    thresh = 40

    acc = {}
    last = None
    curves = 0
    while True:
        p = srv.gen_params()
        b, n = find_weak_b(p, a, bound, big_min, thresh, rnd)
        Gxy, Qxy, n2 = srv.submit(a, b)
        assert n == n2
        res = pohlig(p, a, b, n, Gxy, Qxy, bound)
        for q, (r_, m_) in res.items():
            if q not in acc or acc[q][1] < m_:
                acc[q] = (r_, m_)
        M = 1
        for q, (r_, m_) in acc.items():
            M *= m_
        curves += 1
        last = (p, a, b, n, Gxy, Qxy)
        print(f"[selftest] curve {curves}: smooth_bits added, total modulus bits = {M.bit_length()}", flush=True)
        if M.bit_length() > 175:
            break

    x, M = crt([(r_, m_) for r_, m_ in acc.values()])
    print(f"[selftest] CRT solution bits={x.bit_length()} modulus bits={M.bit_length()}", flush=True)
    cand = x % M
    print("[selftest] recovered d == real d ?", cand == d, flush=True)
    if cand != d:
        print("  recovered:", cand, "\n  real     :", d)
        sys.exit(1)

    # sign on last curve and pass challenge_verify
    p, a, b, n, Gxy, Qxy = last
    E = pari.ellinit([a, b], p)
    G = pari(list(Gxy))
    Q = pari(list(Qxy))
    msg = b"giveflag"
    h = int(sha256(msg).hexdigest(), 16)
    N = n
    for _ in range(2000):
        k = rnd.randrange(1, N)
        if _gcd(k, N) != 1:
            continue
        R = pari.ellmul(E, G, k)
        if len(R) < 2:
            continue
        if int(R[0]) >= N:   # ensure lift_x(r % p) recovers +/-R since rx < N <= p region
            continue
        rx = int(R[0]) % N
        if rx == 0:
            continue
        s = (pow(k, -1, N) * (h + rx * cand)) % N
        if s == 0:
            continue
        # verify with exact challenge logic
        RHS = pari.elladd(E, pari.ellmul(E, G, h % N), pari.ellmul(E, Q, rx % N))
        if len(RHS) < 2:
            continue
        Rc = pari.ellmul(E, R, 1)  # R itself; lift_x(rx) = ±R
        lhs1 = pari.ellmul(E, Rc, s % N)
        lhs2 = pari.ellmul(E, pari.ellneg(E, Rc), s % N)
        if lhs1 == RHS or lhs2 == RHS:
            print(f"[selftest] FORGED valid signature: r={hex(rx)} s={hex(s)}", flush=True)
            print("[selftest] SUCCESS - full pipeline works", flush=True)
            return
    print("[selftest] failed to produce signature")
    sys.exit(1)


if __name__ == "__main__":
    main()
