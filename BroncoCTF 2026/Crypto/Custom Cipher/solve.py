#!/usr/bin/env python3

def trim(p):
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p

def divmod_poly(a, b):
    # Coefficients are in ascending order: c0, c1, ..., cn
    a = trim(a[:])
    b = trim(b[:])
    q = [0] * max(1, len(a) - len(b) + 1)

    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        shift = len(a) - len(b)
        lead = a[-1] // b[-1]
        assert lead * b[-1] == a[-1]
        q[shift] = lead

        for i, coeff in enumerate(b):
            a[i + shift] -= lead * coeff
        trim(a)

    return trim(q), trim(a)

def evaluate(p, x):
    value = 0
    for coeff in reversed(p):
        value = value * x + coeff
    return value

def recover_roots(poly):
    roots = []
    p = poly[:]

    for root in range(256):
        while len(p) > 1 and evaluate(p, root) == 0:
            roots.append(root)
            p, rem = divmod_poly(p, [-root, 1])
            assert rem == [0]

    assert p == [1] and len(roots) == 4
    return roots

data = open("enc.txt", "r", encoding="utf-8").read().splitlines()

pub = list(map(int, data[1].split())) + [1]
blocks = data[3].split("/")

flag = []
for block in blocks:
    values = list(map(int, block.split()))
    order = values[-1]
    encrypted_poly = values[:-1] + [1]

    message_poly, remainder = divmod_poly(encrypted_poly, pub)
    assert remainder == [0]

    sorted_chars = recover_roots(message_poly)
    positions = [(order >> (2 * i)) & 3 for i in range(4)]

    plaintext_block = [""] * 4
    for char_code, position in zip(sorted_chars, positions):
        plaintext_block[position] = chr(char_code)

    flag.extend(plaintext_block)

print("".join(flag).rstrip("\x00"))