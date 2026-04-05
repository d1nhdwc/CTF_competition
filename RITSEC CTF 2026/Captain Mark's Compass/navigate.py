import random

from Crypto.Util.number import getPrime

matrix = [line.strip() for line in open("tmatrix.txt") if line.strip()]

N = len(matrix)
PROBS = [[float(x) for x in line.split()] for line in matrix]


def gen_params():
    P = getPrime(random.randint(256, 1024))
    heads = []
    for _ in range(N):
        a = random.randint(2, P - 1)
        b = random.randint(2, P - 1)
        heads.append((a, b))
    return P, heads


class StateMachine:
    def __init__(self, P, heads, trans):
        self.P = P
        self.heads = heads
        self.trans = trans
        self.curr = random.randint(0, len(heads) - 1)
        self.sval = random.randint(0, P - 1)

    def next(self):
        a, b = self.heads[self.curr]
        self.sval = (a * self.sval + b) % self.P

        val = random.random()
        total = 0.0
        row = self.trans[self.curr]
        nxt = self.curr

        for i, prob in enumerate(row):
            total += prob
            if val < total:
                nxt = i
                break

        self.curr = nxt
        return self.sval


def enc(flag, lcg):
    fbytes = flag.encode()
    strm = [lcg.next() & 0xFF for _ in range(len(fbytes))]

    return bytes([k ^ f for k, f in zip(strm, fbytes)])


P, heads = gen_params()
lcg = StateMachine(P, heads, PROBS)

tdat = [lcg.next() for _ in range(850)]

FLAG = open("flag.txt").read()
ctext = enc(FLAG, lcg)

with open("logbook.txt", "w") as f:
    f.write(f"Log: {tdat}\n")
    f.write(f"Ciphertext: {ctext.hex()}\n")

print(f"P = {P}")
print(f"Heads: {heads}")
