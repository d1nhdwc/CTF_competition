#!/usr/bin/env python3
from pwn import *
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK_SIZE = 16
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
GCM_REDUCTION = 0xE1000000000000000000000000000000

N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF


# -----------------------------
# GF(2^128) / GHASH helpers
# -----------------------------
def gf_mul(x, y):
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ GCM_REDUCTION
        else:
            v >>= 1
    return z & MASK128


def ghash(subkey, blocks):
    tag = 0
    for block in blocks:
        tag = gf_mul(tag ^ block, subkey)
    return tag


LEN_BLOCK = int.from_bytes((0).to_bytes(8, "big") + (16 * 8).to_bytes(8, "big"), "big")


def ghash_low64_linear_forms(cipher_int):
    forms = [0] * 64
    for j in range(128):
        h = 1 << j
        g = ghash(h, [cipher_int, LEN_BLOCK]) & MASK64
        x = g
        while x:
            bit = (x & -x).bit_length() - 1
            forms[bit] ^= 1 << j
            x &= x - 1
    return forms


# -----------------------------
# Symbolic MT19937 over GF(2)
# -----------------------------
def xorw(a, b):
    return tuple(x ^ y for x, y in zip(a, b))


def and_const(a, c):
    return tuple(a[j] if ((c >> j) & 1) else 0 for j in range(32))


def orw(a, b):
    return tuple(x ^ y for x, y in zip(a, b))


def rshift(a, s):
    return tuple(a[j + s] if j + s < 32 else 0 for j in range(32))


def lshift(a, s):
    return tuple(a[j - s] if j - s >= 0 else 0 for j in range(32))


def temper_symbolic(x):
    y = list(x)
    t = rshift(tuple(y), 11)
    y = [a ^ b for a, b in zip(y, t)]

    t = and_const(lshift(tuple(y), 7), 0x9D2C5680)
    y = [a ^ b for a, b in zip(y, t)]

    t = and_const(lshift(tuple(y), 15), 0xEFC60000)
    y = [a ^ b for a, b in zip(y, t)]

    t = rshift(tuple(y), 18)
    y = [a ^ b for a, b in zip(y, t)]
    return tuple(y)


def twist_word_from_y(y):
    z = rshift(y, 1)
    lsb = y[0]
    return tuple(z[j] ^ (lsb if ((MATRIX_A >> j) & 1) else 0) for j in range(32))


def twist_state_symbolic(state):
    mt = state[:]

    for kk in range(N - M):
        y = orw(and_const(mt[kk], UPPER_MASK), and_const(mt[kk + 1], LOWER_MASK))
        mt[kk] = xorw(mt[kk + M], twist_word_from_y(y))

    for kk in range(N - M, N - 1):
        y = orw(and_const(mt[kk], UPPER_MASK), and_const(mt[kk + 1], LOWER_MASK))
        mt[kk] = xorw(mt[kk + (M - N)], twist_word_from_y(y))

    y = orw(and_const(mt[N - 1], UPPER_MASK), and_const(mt[0], LOWER_MASK))
    mt[N - 1] = xorw(mt[M - 1], twist_word_from_y(y))
    return mt


def gen_symbolic_output_forms(num_outputs):
    state = [tuple(1 << (32 * i + j) for j in range(32)) for i in range(N)]
    idx = N
    outs = []

    while len(outs) < num_outputs:
        if idx >= N:
            state = twist_state_symbolic(state)
            idx = 0
        outs.append(temper_symbolic(state[idx]))
        idx += 1

    return outs


# -----------------------------
# GF(2) solve
# -----------------------------
def solve_h_and_seed_state(queries):
    out_forms = gen_symbolic_output_forms(2 * len(queries))
    pivots = {}
    SHIFT_STATE = 129

    for qi, (_, ciphertext, tag) in enumerate(queries):
        low_obs = int.from_bytes(tag, "big") & MASK64
        g_forms = ghash_low64_linear_forms(int.from_bytes(ciphertext, "big"))

        w0_forms = out_forms[2 * qi]
        w1_forms = out_forms[2 * qi + 1]

        for b in range(64):
            row = (low_obs >> b) & 1
            row |= g_forms[b] << 1
            row |= (w1_forms[b] if b < 32 else w0_forms[b - 32]) << SHIFT_STATE

            while row:
                p = row.bit_length() - 1
                if p == 0:
                    raise RuntimeError("inconsistent system")
                if p in pivots:
                    row ^= pivots[p]
                else:
                    pivots[p] = row
                    break

    sol = 0
    for p in sorted(pivots):
        row = pivots[p]
        rhs = row & 1
        if ((row & sol).bit_count() & 1) ^ rhs:
            sol |= 1 << p

    h = 0
    for j in range(128):
        h |= ((sol >> (1 + j)) & 1) << j

    state = []
    for i in range(624):
        state.append((sol >> (129 + 32 * i)) & 0xFFFFFFFF)

    state[0] = 0x80000000
    return h, state


# -----------------------------
# Reverse Python seeding
# -----------------------------
def f1(x):
    return ((x ^ (x >> 30)) * 1664525) & 0xFFFFFFFF


def f2(x):
    return ((x ^ (x >> 30)) * 1566083941) & 0xFFFFFFFF


def init_genrand(seed):
    mt = [0] * N
    mt[0] = seed & 0xFFFFFFFF
    for i in range(1, N):
        mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
    return mt


def reverse_second_loop(final_state):
    mt = final_state[:]
    mt[0] = mt[623]
    mt[1] = ((mt[1] + 1) & 0xFFFFFFFF) ^ f2(mt[0])

    for i in range(623, 1, -1):
        mt[i] = ((mt[i] + i) & 0xFFFFFFFF) ^ f2(mt[i - 1])

    mt[0] = mt[623]
    return mt


def recover_key_words_from_seed_state(seed_state, max_keylen=8):
    s1 = reverse_second_loop(seed_state)
    init = init_genrand(19650218)
    candidates = []

    for keylen in range(1, max_keylen + 1):
        vals = [[] for _ in range(keylen)]
        ok = True

        for i in range(3, 624):
            j = (i - 1) % keylen
            cand = (s1[i] - (init[i] ^ f1(s1[i - 1])) - j) & 0xFFFFFFFF
            vals[j].append(cand)

        keys = []
        for v in vals:
            if len(set(v)) != 1:
                ok = False
                break
            keys.append(v[0])

        if not ok:
            continue

        j_last = 623 % keylen
        mt1_after_first_update = ((s1[1] - keys[j_last] - j_last) & 0xFFFFFFFF) ^ f1(s1[0])

        cand2 = (s1[2] - (init[2] ^ f1(mt1_after_first_update)) - ((2 - 1) % keylen)) & 0xFFFFFFFF
        if cand2 != keys[(2 - 1) % keylen]:
            continue

        cand0 = (mt1_after_first_update - (init[1] ^ f1(init[0])) - 0) & 0xFFFFFFFF
        if cand0 != keys[0]:
            continue

        candidates.append((keylen, keys))

    return candidates


def recover_master_key(seed_state):
    cands = recover_key_words_from_seed_state(seed_state, 8)
    if not cands:
        raise RuntimeError("failed to recover python seed")

    keylen, key_words = cands[0]
    seed = 0
    for i, w in enumerate(key_words):
        seed |= w << (32 * i)

    return seed.to_bytes(32, "big")


# -----------------------------
# pwntools I/O
# -----------------------------
def parse_banner(blob):
    text = blob.decode()
    flag_nonce = bytes.fromhex(re.search(r"flag_nonce = ([0-9a-f]+)", text).group(1))
    flag_ct    = bytes.fromhex(re.search(r"flag_ciphertext = ([0-9a-f]+)", text).group(1))
    flag_tag   = bytes.fromhex(re.search(r"flag_tag = ([0-9a-f]+)", text).group(1))
    budget     = int(re.search(r"query budget = (\d+)", text).group(1))
    return flag_nonce, flag_ct, flag_tag, budget


def parse_query(blob):
    text = blob.decode()
    nonce = bytes.fromhex(re.search(r"nonce = ([0-9a-f]+)", text).group(1))
    ct    = bytes.fromhex(re.search(r"ciphertext = ([0-9a-f]+)", text).group(1))
    tag   = bytes.fromhex(re.search(r"tag = ([0-9a-f]+)", text).group(1))
    return nonce, ct, tag


def collect_queries(host, port):
    io = remote(host, port, ssl=True)

    banner = io.recvuntil(b'> ')
    flag_nonce, flag_ct, flag_tag, budget = parse_banner(banner)
    log.info(f"budget = {budget}")

    queries = []
    for i in range(budget):
        io.sendline(b"1")
        blob = io.recvuntil(b'> ')
        queries.append(parse_query(blob))
        if (i + 1) % 50 == 0:
            log.info(f"collected {i + 1}/{budget}")

    io.sendline(b"2")
    io.close()

    return flag_nonce, flag_ct, flag_tag, queries


def main():
    host = "manytags.opus4-7.b01le.rs"
    port = 8443

    flag_nonce, flag_ct, flag_tag, queries = collect_queries(host, port)
    log.info("solving linear system...")
    _, seed_state = solve_h_and_seed_state(queries)

    log.info("recovering master key...")
    master_key = recover_master_key(seed_state)
    log.success(f"master_key = {master_key.hex()}")

    flag = AESGCM(master_key).decrypt(flag_nonce, flag_ct + flag_tag, None)
    log.success(f"flag = {flag.decode(errors='replace')}")


if __name__ == "__main__":
    main()
