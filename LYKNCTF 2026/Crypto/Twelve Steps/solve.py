#!/usr/bin/env python3
import socket
import re
import math
import sys
from functools import reduce

HOST = "51.79.140.18"
PORT = 18213

def recv_until(sock, marker=b"out[12] ="):
    data = b""
    sock.settimeout(10)

    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk

    return data

def egcd(a, b):
    if b == 0:
        return abs(a), 1 if a > 0 else -1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def invmod(a, m):
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m

def recover_modulus(xs):
    ds = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]

    vals = []
    for i in range(len(ds) - 2):
        z = ds[i + 2] * ds[i] - ds[i + 1] * ds[i + 1]
        if z != 0:
            vals.append(abs(z))

    if not vals:
        raise RuntimeError("cannot recover modulus")

    m = reduce(math.gcd, vals)
    return m

def recover_a_c(xs, m):
    for i in range(len(xs) - 2):
        d1 = (xs[i + 1] - xs[i]) % m
        d2 = (xs[i + 2] - xs[i + 1]) % m

        if math.gcd(d1, m) != 1:
            continue

        a = d2 * invmod(d1, m) % m
        c = (xs[i + 1] - a * xs[i]) % m

        ok = True
        for j in range(len(xs) - 1):
            if (a * xs[j] + c) % m != xs[j + 1]:
                ok = False
                break

        if ok:
            return a, c

    raise RuntimeError("cannot recover a,c")

def main():
    host = sys.argv[1] if len(sys.argv) >= 2 else HOST
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else PORT

    s = socket.create_connection((host, port), timeout=10)

    banner = recv_until(s)
    text = banner.decode(errors="replace")

    print(text, end="")

    xs = [int(x) for x in re.findall(r"out\[\d+\]\s*=\s*(\d+)", text)]

    if len(xs) < 12:
        print("[!] Could not parse 12 outputs")
        print("[!] parsed:", xs)
        return

    print("\n[+] parsed outputs:", xs)

    m = recover_modulus(xs)
    a, c = recover_a_c(xs, m)

    pred = (a * xs[-1] + c) % m

    print("[+] m =", m)
    print("[+] a =", a)
    print("[+] c =", c)
    print("[+] predicted out[12] =", pred)

    s.sendall(str(pred).encode() + b"\n")

    try:
        resp = s.recv(4096)
        print(resp.decode(errors="replace"))
    except Exception:
        pass

    s.close()

if __name__ == "__main__":
    main()
