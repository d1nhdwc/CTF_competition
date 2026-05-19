#!/usr/bin/env python3
import argparse
import random
import socket
from math import gcd, lcm

P = 10007
A = 2

DEFAULT_HOST = "tjc.tf"
DEFAULT_PORT = 31313
DEFAULT_TARGET_BITS = 400


def mod_inv(x, p):
    return pow(x % p, -1, p)


def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if x1 == x2 and y1 == y2:
        s = (3 * x1 * x1 + A) * mod_inv(2 * y1, P)
    else:
        s = (y2 - y1) * mod_inv(x2 - x1, P)
    s %= P

    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, P1):
    result = None
    addend = P1

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def point_order(G, limit=30000):
    curr = None
    for k in range(1, limit + 1):
        curr = point_add(curr, G)
        if curr is None:
            return k
    return None


def build_dlog_table(G, order):
    table = {None: 0}
    curr = None
    for k in range(1, order):
        curr = point_add(curr, G)
        table[curr] = k
    return table


def combine_congruence(a1, m1, a2, m2):
    g = gcd(m1, m2)
    if (a2 - a1) % g != 0:
        raise ValueError(f"inconsistent congruences: x = {a1} mod {m1}, x = {a2} mod {m2}")

    if m2 == g:
        return a1 % m1, m1

    step = ((a2 - a1) // g) * pow(m1 // g, -1, m2 // g)
    step %= m2 // g

    mod = (m1 // g) * m2
    value = (a1 + m1 * step) % mod
    return value, mod


def int_to_bytes(n):
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def ceil_div(a, b):
    return -((-a) // b)


def extract_flag(value, modulus, prefix=b"tjctf{", suffix=b"}", max_len=80):
    min_len = max(1, len(prefix) + len(suffix))
    for byte_len in range(min_len, max_len + 1):
        low = 0 if byte_len == 1 else 1 << (8 * (byte_len - 1))
        high = 1 << (8 * byte_len)
        t_min = max(0, ceil_div(low - value, modulus))
        t_max = (high - 1 - value) // modulus

        for t in range(t_min, t_max + 1):
            candidate = value + t * modulus
            flag = int_to_bytes(candidate)
            if flag.startswith(prefix) and flag.endswith(suffix):
                return flag

    return None


def pick_invalid_curve_points(target_bits, seed):
    rng = random.Random(seed)
    combined_modulus = 1
    picked = []
    attempts = 0

    while combined_modulus.bit_length() < target_bits:
        attempts += 1
        G = (rng.randrange(P), rng.randrange(P))
        order = point_order(G)
        if order in (None, 1):
            continue

        new_modulus = lcm(combined_modulus, order)
        if new_modulus == combined_modulus:
            continue

        picked.append(
            {
                "point": G,
                "order": order,
                "table": build_dlog_table(G, order),
            }
        )
        combined_modulus = new_modulus

    return picked, combined_modulus, attempts


def recv_until(sock, marker):
    data = bytearray()
    while not data.endswith(marker):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def recv_line(sock):
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
        if chunk == b"\n":
            return bytes(data)


def query_remote(sock, G):
    recv_until(sock, b"x = ")
    sock.sendall(f"{G[0]}\n".encode())
    recv_until(sock, b"y = ")
    sock.sendall(f"{G[1]}\n".encode())
    recv_until(sock, b"Q = ")

    line = recv_line(sock).strip().decode()
    if line == "inf":
        return None

    parts = line.split()
    if len(parts) != 2:
        raise ValueError(f"unexpected server response: {line!r}")
    return int(parts[0]), int(parts[1])


def solve_with_oracle(oracle, points, max_len):
    value = 0
    modulus = 1

    for idx, item in enumerate(points, 1):
        G = item["point"]
        order = item["order"]
        Q = oracle(G)
        residue = item["table"].get(Q)
        if residue is None:
            raise ValueError(f"point {G} produced {Q}, which is not in the generated subgroup")

        value, modulus = combine_congruence(value, modulus, residue, order)
        print(
            f"[{idx:02d}/{len(points)}] G={G} order={order:<5} "
            f"residue={residue:<5} modulus_bits={modulus.bit_length()}"
        )

    flag = extract_flag(value, modulus, max_len=max_len)
    return value, modulus, flag


def run_self_test(target_bits, seed, max_len):
    fake_flag = b"tjctf{test_flag}"
    secret_d = int.from_bytes(fake_flag, "big")

    points, total_modulus, attempts = pick_invalid_curve_points(target_bits, seed)
    print(
        f"[*] Picked {len(points)} invalid-curve points in {attempts} attempts "
        f"(lcm bits = {total_modulus.bit_length()})"
    )

    oracle = lambda G: scalar_mul(secret_d, G)
    _, modulus, recovered = solve_with_oracle(oracle, points, max_len)

    if recovered != fake_flag:
        raise RuntimeError(f"self-test failed: recovered {recovered!r}")

    print(f"[+] Self-test OK: {recovered.decode()}")
    print(f"[*] Final CRT modulus bits: {modulus.bit_length()}")


def run_remote(host, port, target_bits, seed, max_len):
    points, total_modulus, attempts = pick_invalid_curve_points(target_bits, seed)
    print(
        f"[*] Picked {len(points)} invalid-curve points in {attempts} attempts "
        f"(lcm bits = {total_modulus.bit_length()})"
    )
    print(f"[*] Connecting to {host}:{port}")

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(10)
        _, modulus, flag = solve_with_oracle(lambda G: query_remote(sock, G), points, max_len)

    print(f"[*] Final CRT modulus bits: {modulus.bit_length()}")
    if flag is None:
        print("[-] Could not isolate a unique tjctf{...} candidate.")
        return

    print(f"[+] Flag: {flag.decode()}")


def main():
    parser = argparse.ArgumentParser(description="TJCTF invalid-curve solver")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--target-bits", type=int, default=DEFAULT_TARGET_BITS)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-len", type=int, default=80)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        run_self_test(args.target_bits, args.seed, args.max_len)
        return

    run_remote(args.host, args.port, args.target_bits, args.seed, args.max_len)


if __name__ == "__main__":
    main()
