from math import gcd, isqrt
from random import randrange
from sympy import primerange

n = 14884800451955950069113725819582523452585625680964352925405287702945124871438012573975746640883842103042984750487942943421571681652252352348393111535120212824144300409490952092961805337273025660675021221223760281669849366431560452175211927388902210616902198236233541611572685032003626072414569507837860098262478925981342654902998086422642563797070782607595233706836044689489106803015979

B = 1 << 16  # >= 2^15 smooth bound used by challenge

# product of prime powers up to B (the ECM "k" multiplier)
def make_k(B):
    k = 1
    for p in primerange(2, B + 1):
        pe = p
        while pe * p <= B:
            pe *= p
        k *= pe
    return k

# Elliptic curve y^2 = x^3 + b mod n (CM by Z[omega], j=0).
# Affine add; raises with the gcd factor if an inversion fails mod p.
class Factor(Exception):
    def __init__(self, f): self.f = f

def inv(a, n):
    g = gcd(a % n, n)
    if g != 1:
        raise Factor(g)
    return pow(a, -1, n)

def add(P, Q, b, n):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % n == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 % n) * inv(2 * y1 % n, n) % n
    else:
        lam = (y2 - y1) % n * inv((x2 - x1) % n, n) % n
    x3 = (lam * lam - x1 - x2) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3)

def mul(k, P, b, n):
    R = None
    while k:
        if k & 1:
            R = add(R, P, b, n)
        P = add(P, P, b, n)
        k >>= 1
    return R

def attack(n, B):
    # apply prime powers one at a time so a smooth-order curve triggers early
    pps = []
    for p in primerange(2, B + 1):
        pe = p
        while pe * p <= B:
            pe *= p
        pps.append(pe)
    tries = 0
    while True:
        tries += 1
        x0 = randrange(n); y0 = randrange(n)
        b = (y0 * y0 - x0 * x0 * x0) % n  # ensure (x0,y0) on curve
        P = (x0, y0)
        try:
            for pe in pps:
                P = mul(pe, P, b, n)
                if P is None:
                    break
        except Factor as e:
            g = e.f
            if 1 < g < n:
                print("found on curve", tries)
                return g

print("factoring...")
p = attack(n, B)
q = n // p
print("p =", p)
print("q =", q)
print("p*q == n:", p * q == n)

# decrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

c = bytes.fromhex("25fed2dac3d3562dc8824679a10693b6fef217da7eff6148837c4e5cf26ad9a7a5bb61de9cf0acbc260fb217cfd41d3b106b5c60de887e46645f2d8ab209e13ed9fdb2e1775353772976a8741da05b11931c881a763b6ac41e5516e323fd2db3001a1a4c0fe55bd31071cd9f81e830b49a80846a7c859b669cfdbfe41951fe46fdf529b3dc6924f949264641cc0b9429f423c2d2a8334a5dbb879f32c918a87b")
e = 65537
d = pow(e, -1, (p - 1) * (q - 1))
key = RSA.construct((n, e, d, p, q))
print(PKCS1_OAEP.new(key).decrypt(c))
