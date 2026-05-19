#!/usr/bin/env python3
import argparse
import re
import socket
import time
from fractions import Fraction


DEFAULT_HOST = "tjc.tf"
DEFAULT_PORT = 31001


class Remote:
    def __init__(self, host, port, timeout=10):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(timeout)
        self.buf = b""

    def recv_until(self, token):
        if isinstance(token, str):
            token = token.encode()
        while token not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:idx], self.buf[idx:]
        return out

    def recv_line(self):
        return self.recv_until(b"\n")

    def send_line(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def send(self, data):
        self.sock.sendall(data)

    def close(self):
        self.sock.close()


def parse_parameters(banner):
    vals = {}
    for name in ("n", "e", "ciphertext"):
        match = re.search(rb"(?m)^" + name.encode() + rb" = ([0-9]+)$", banner)
        if not match:
            raise ValueError(f"could not parse {name}")
        vals[name] = int(match.group(1))
    return vals["n"], vals["e"], vals["ciphertext"]


def oracle(remote, candidate):
    remote.recv_until(b"> ")
    remote.send_line("1")
    remote.recv_until(b"ciphertext = ")
    remote.send_line(str(candidate))
    return recv_lsb(remote)


def recv_lsb(remote):
    while True:
        match = re.search(rb"lsb = ([01])", remote.buf)
        if match:
            bit = int(match.group(1))
            remote.buf = remote.buf[match.end():]
            return bit
        chunk = remote.sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed while waiting for oracle bit")
        remote.buf += chunk


def long_to_bytes(value):
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def recover_plaintext(remote, n, e, ciphertext, delay=0.2, safe=False, max_bytes=48):
    multiplier = pow(2, e, n)
    probe = ciphertext
    upper_bound = 1 << (8 * max_bytes)

    # One query halves the interval. A couple extra rounds eliminate boundary
    # ambiguity from the rational interval endpoints.
    rounds = n.bit_length() + 2
    probes = {}
    known_bits = {}
    for i in range(1, rounds + 1):
        probe = (probe * multiplier) % n
        if upper_bound <= n and (upper_bound << i) <= n:
            known_bits[i] = 0
        else:
            probes[i] = probe

    if known_bits:
        print(f"[+] skipped {len(known_bits)} guaranteed-zero oracle bits")

    remote.recv_until(b"> ")
    bits = {}
    for done, (i, probe) in enumerate(probes.items(), 1):
        remote.send_line("1")
        if safe:
            remote.recv_until(b"ciphertext = ")
        else:
            time.sleep(delay)
        remote.send_line(str(probe))
        bits[i] = recv_lsb(remote)

        if done % 64 == 0 or done == len(probes):
            print(f"[+] received {done:03d}/{len(probes)} oracle bits")

    low = Fraction(0, 1)
    high = Fraction(n, 1)
    for i in range(1, rounds + 1):
        bit = known_bits.get(i, bits.get(i))
        if bit is None:
            raise ValueError(f"missing oracle bit {i}")
        mid = (low + high) / 2
        if bit == 0:
            high = mid
        else:
            low = mid

        if i % 64 == 0 or i == rounds:
            width = high - low
            print(f"[+] query {i:03d}/{rounds}, interval width ~= {float(width):.3g}")

    start = max(0, int(low))
    end = min(n - 1, int(high) + 2)

    for candidate in range(start, end + 1):
        if pow(candidate, e, n) == ciphertext:
            return candidate

    # Fallback for the extremely unlikely case that the true integer sits just
    # outside the rounded endpoints.
    center = int((low + high) / 2)
    for delta in range(1, 32):
        for candidate in (center - delta, center + delta):
            if 0 <= candidate < n and pow(candidate, e, n) == ciphertext:
                return candidate

    raise ValueError("failed to identify plaintext integer")


def main():
    parser = argparse.ArgumentParser(description="Solve TJCTF bit-leak RSA parity oracle")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--delay", type=float, default=0.2,
                        help="delay between sending menu choice and ciphertext in fast mode")
    parser.add_argument("--safe", action="store_true",
                        help="wait for every prompt instead of using timed fast mode")
    parser.add_argument("--timeout", type=float, default=15,
                        help="socket timeout in seconds")
    parser.add_argument("--max-bytes", type=int, default=48,
                        help="assume the flag is at most this many bytes")
    args = parser.parse_args()

    remote = Remote(args.host, args.port, timeout=args.timeout)
    try:
        banner = remote.recv_until(b"you may ask for up to")
        banner += remote.recv_line()
        n, e, ciphertext = parse_parameters(banner)

        print(f"[+] n bits: {n.bit_length()}")
        print(f"[+] e: {e}")
        print("[+] running parity oracle attack")

        message = recover_plaintext(remote, n, e, ciphertext, delay=args.delay,
                                    safe=args.safe, max_bytes=args.max_bytes)
        plaintext = long_to_bytes(message)
        print(f"[+] plaintext bytes: {plaintext!r}")

        try:
            print(plaintext.decode())
        except UnicodeDecodeError:
            print(plaintext.hex())
    finally:
        remote.close()


if __name__ == "__main__":
    main()
