#!/usr/bin/env python3

from __future__ import annotations

import argparse
import random
import re
import socket
import ssl
import sys
from math import gcd, isqrt
from typing import Dict, List, Optional, Tuple


PROMPT_MARKER = b"bb>"


def mod_inv(a: int, p: int) -> int:
    return pow(a, -1, p)


def divisors_upto(n: int, limit: int) -> List[int]:
    out = set()
    for d in range(1, isqrt(n) + 1):
        if n % d == 0:
            if 1 < d <= limit:
                out.add(d)
            q = n // d
            if 1 < q <= limit:
                out.add(q)
    return sorted(out)


class Matrix3:
    __slots__ = ("p", "a")

    def __init__(self, p: int, entries: Tuple[int, ...]) -> None:
        self.p = p
        self.a = tuple(x % p for x in entries)

    @classmethod
    def identity(cls, p: int) -> "Matrix3":
        return cls(p, (1, 0, 0, 0, 1, 0, 0, 0, 1))

    def __mul__(self, other: "Matrix3") -> "Matrix3":
        p = self.p
        a = self.a
        b = other.a
        return Matrix3(
            p,
            (
                a[0] * b[0] + a[1] * b[3] + a[2] * b[6],
                a[0] * b[1] + a[1] * b[4] + a[2] * b[7],
                a[0] * b[2] + a[1] * b[5] + a[2] * b[8],
                a[3] * b[0] + a[4] * b[3] + a[5] * b[6],
                a[3] * b[1] + a[4] * b[4] + a[5] * b[7],
                a[3] * b[2] + a[4] * b[5] + a[5] * b[8],
                a[6] * b[0] + a[7] * b[3] + a[8] * b[6],
                a[6] * b[1] + a[7] * b[4] + a[8] * b[7],
                a[6] * b[2] + a[7] * b[5] + a[8] * b[8],
            ),
        )

    def det(self) -> int:
        p = self.p
        a = self.a
        det = (
            a[0] * (a[4] * a[8] - a[5] * a[7])
            - a[1] * (a[3] * a[8] - a[5] * a[6])
            + a[2] * (a[3] * a[7] - a[4] * a[6])
        )
        return det % p

    def inverse(self) -> "Matrix3":
        p = self.p
        rows = [
            [self.a[0], self.a[1], self.a[2], 1, 0, 0],
            [self.a[3], self.a[4], self.a[5], 0, 1, 0],
            [self.a[6], self.a[7], self.a[8], 0, 0, 1],
        ]
        for col in range(3):
            pivot = None
            for row in range(col, 3):
                if rows[row][col] % p != 0:
                    pivot = row
                    break
            if pivot is None:
                raise ValueError("matrix is singular")
            if pivot != col:
                rows[col], rows[pivot] = rows[pivot], rows[col]
            inv_pivot = mod_inv(rows[col][col], p)
            rows[col] = [(x * inv_pivot) % p for x in rows[col]]
            for row in range(3):
                if row == col:
                    continue
                factor = rows[row][col] % p
                if factor:
                    rows[row] = [
                        (rows[row][k] - factor * rows[col][k]) % p for k in range(6)
                    ]
        return Matrix3(p, tuple(rows[r][c] for r in range(3) for c in range(3, 6)))

    def conjugate_by_diag(self, d: int) -> "Matrix3":
        p = self.p
        dinv = mod_inv(d, p)
        a = list(self.a)
        a[1] = (a[1] * d) % p
        a[2] = (a[2] * d) % p
        a[3] = (a[3] * dinv) % p
        a[6] = (a[6] * dinv) % p
        return Matrix3(p, tuple(a))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Matrix3) and self.a == other.a and self.p == other.p

    def __hash__(self) -> int:
        return hash((self.p, self.a))


def hol_mul(x: Tuple[Matrix3, int], y: Tuple[Matrix3, int], p: int) -> Tuple[Matrix3, int]:
    a, c1 = x
    b, c2 = y
    return a * b.conjugate_by_diag(c1), (c1 * c2) % p


def hol_pow(base: Tuple[Matrix3, int], e: int, p: int) -> Tuple[Matrix3, int]:
    one = Matrix3.identity(p)
    result = (one, 1)
    cur = base
    k = e
    while k > 0:
        if k & 1:
            result = hol_mul(result, cur, p)
        cur = hol_mul(cur, cur, p)
        k >>= 1
    return result


class LocalOracle:
    def __init__(self, p: int, bound: int, seed: Optional[int] = None) -> None:
        self.rand = random.Random(seed)
        self.p = p
        self.bound = bound
        self.max_c_order = 8
        self.table: List[Matrix3] = []
        self.index: Dict[Matrix3, int] = {}
        self.one = self._add(Matrix3.identity(p))
        self.round = 0
        self.finished = False
        self.last_secret: Optional[int] = None

    def _add(self, x: Matrix3) -> int:
        h = self.index.get(x)
        if h is not None:
            return h
        self.table.append(x)
        handle = len(self.table)
        self.index[x] = handle
        return handle

    def _rand_gl3(self) -> int:
        while True:
            m = Matrix3(self.p, tuple(self.rand.randrange(self.p) for _ in range(9)))
            if m.det() != 0:
                return self._add(m)

    def start_round(self) -> bool:
        if self.finished:
            return False
        self.round += 1
        choices = divisors_upto(self.p - 1, self.max_c_order)
        self.c_order = self.rand.choice(choices)
        gen = 3
        while gcd(gen, self.p) != 1:
            gen += 1
        d = pow(gen, (self.p - 1) // self.c_order, self.p)
        while pow(d, self.c_order, self.p) != 1 or any(
            pow(d, k, self.p) == 1 for k in range(1, self.c_order)
        ):
            gen += 1
            d = pow(gen, (self.p - 1) // self.c_order, self.p)
        self.d = d
        self.c_handle = self._add(Matrix3(self.p, (d, 0, 0, 0, 1, 0, 0, 0, 1)))
        self.g = self._rand_gl3()
        self.secret = self.rand.randint(0, self.bound)
        self.last_secret = self.secret
        h = hol_pow((self.table[self.g - 1], self.d), self.secret, self.p)[0]
        self.h = self._add(h)
        return True

    def mul(self, a: int, b: int) -> int:
        return self._add(self.table[a - 1] * self.table[b - 1])

    def inv(self, a: int) -> int:
        return self._add(self.table[a - 1].inverse())

    def phi(self, a: int) -> int:
        return self._add(self.table[a - 1].conjugate_by_diag(self.d))

    def submit(self, x: int) -> bool:
        ok = hol_pow((self.table[self.g - 1], self.d), x, self.p)[0] == self.table[self.h - 1]
        return ok


class RemoteOracle:
    def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        raw = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(raw, server_hostname=host)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.closed = False
        self.max_handle = 0

    def _recv_until_prompt(self) -> str:
        while PROMPT_MARKER not in self.buf and not self.closed:
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError as exc:
                raise TimeoutError(
                    f"timed out waiting for prompt from {self.host}:{self.port}"
                ) from exc
            if not chunk:
                self.closed = True
                break
            self.buf += chunk
        if PROMPT_MARKER in self.buf:
            idx = self.buf.index(PROMPT_MARKER)
            out = self.buf[:idx]
            rest = self.buf[idx + len(PROMPT_MARKER) :]
            if rest.startswith(b" "):
                rest = rest[1:]
            self.buf = rest
            return out.decode(errors="replace")
        out = self.buf
        self.buf = b""
        return out.decode(errors="replace")

    def _decode_buffer(self) -> str:
        return self.buf.decode(errors="replace")

    def recv_until_round_or_prompt(self) -> Optional[str]:
        while not self.closed:
            if PROMPT_MARKER in self.buf:
                return self._recv_until_prompt()
            text = self._decode_buffer()
            if ROUND_RE.search(text) or "Challenge failed." in text or "flag{" in text or "bctf{" in text:
                try:
                    chunk = self.sock.recv(4096)
                except TimeoutError:
                    out = text
                    self.buf = b""
                    return out
                if not chunk:
                    self.closed = True
                    out = text
                    self.buf = b""
                    return out
                self.buf += chunk
                continue
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError as exc:
                raise TimeoutError(
                    f"timed out waiting for round data from {self.host}:{self.port}"
                ) from exc
            if not chunk:
                self.closed = True
                break
            self.buf += chunk
        if self.buf:
            out = self._decode_buffer()
            self.buf = b""
            return out
        return None

    def start_round(self) -> Optional[str]:
        text = self.recv_until_round_or_prompt()
        if text:
            self._update_max_handle_from_text(text)
        return text

    def command(self, cmd: str) -> str:
        self.sock.sendall(cmd.encode() + b"\n")
        text = self.recv_until_round_or_prompt()
        text = "" if text is None else text
        self._update_max_handle_from_text(text)
        return text

    def command_many(self, cmds: List[str]) -> List[str]:
        if not cmds:
            return []
        self.sock.sendall(("".join(f"{cmd}\n" for cmd in cmds)).encode())
        outs = []
        for _ in cmds:
            out = self._recv_until_prompt()
            self._update_max_handle_from_text(out)
            outs.append(out)
        return outs

    def _update_max_handle_from_text(self, text: str) -> None:
        for tok in re.findall(r"\b\d+\b", text):
            self.max_handle = max(self.max_handle, int(tok))

    def chain_mul_right(self, start: int, generator: int, count: int, block: int = 32) -> List[int]:
        out = []
        cur = start
        done = 0
        while done < count:
            todo = min(block, count - done)
            predicted = []
            cmds = []
            pred_cur = cur
            pred_next = self.max_handle
            for _ in range(todo):
                cmds.append(f"mul {pred_cur} {generator}")
                pred_next += 1
                predicted.append(pred_next)
                pred_cur = pred_next
            responses = self.command_many(cmds)
            mismatch_at = None
            for idx, (resp, expect) in enumerate(zip(responses, predicted)):
                lines = [line.strip() for line in resp.splitlines() if line.strip()]
                if not lines or not lines[-1].isdigit():
                    mismatch_at = idx
                    break
                actual = int(lines[-1])
                out.append(actual)
                cur = actual
                self.max_handle = max(self.max_handle, actual)
                if actual != expect:
                    mismatch_at = idx + 1
                    break
            if mismatch_at is None:
                done += todo
                continue
            done += mismatch_at
            while done < count:
                cur = self.mul(cur, generator)
                out.append(cur)
                done += 1
        return out

    def mul(self, a: int, b: int) -> int:
        return int(self.command(f"mul {a} {b}").strip().splitlines()[-1])

    def inv(self, a: int) -> int:
        return int(self.command(f"inv {a}").strip().splitlines()[-1])

    def phi(self, a: int) -> int:
        return int(self.command(f"phi {a}").strip().splitlines()[-1])

    def submit(self, x: int) -> str:
        return self.command(f"submit {x}")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


ROUND_RE = re.compile(
    r"c order=(?P<c_order>\d+).*?Find any x in \[0, (?P<bound>\d+)\].*?"
    r"one=(?P<one>\d+) g=(?P<g>\d+) c=(?P<c>\d+) h=(?P<h>\d+)",
    re.S,
)


def parse_round(text: str) -> Dict[str, int]:
    m = ROUND_RE.search(text)
    if not m:
        raise ValueError(f"could not parse round setup:\n{text}")
    return {k: int(v) for k, v in m.groupdict().items()}


def bsgs_handle(
    oracle,
    generator: int,
    target: int,
    one: int,
    limit: int,
    progress_label: Optional[str] = None,
) -> Optional[int]:
    if limit < 0:
        return None
    step = isqrt(limit) + 1
    baby = {one: 0}
    cur = one
    if progress_label is not None:
        print(f"[remote] {progress_label}: building baby table size~{step}", flush=True)
    if hasattr(oracle, "chain_mul_right"):
        chain = oracle.chain_mul_right(one, generator, step - 1)
        for j, cur in enumerate(chain, 1):
            baby.setdefault(cur, j)
    else:
        for j in range(1, step):
            cur = oracle.mul(cur, generator)
            baby.setdefault(cur, j)
    factor = oracle.inv(generator)
    if hasattr(oracle, "chain_mul_right"):
        giant_factor = oracle.chain_mul_right(one, factor, step)[-1]
    else:
        giant_factor = one
        for _ in range(step):
            giant_factor = oracle.mul(giant_factor, factor)
    cur = target
    if progress_label is not None:
        print(f"[remote] {progress_label}: giant-step search", flush=True)
    if hasattr(oracle, "chain_mul_right"):
        giant_chain = [target] + oracle.chain_mul_right(target, giant_factor, step)
    else:
        giant_chain = None
    for i in range(step + 1):
        if giant_chain is not None:
            cur = giant_chain[i]
        j = baby.get(cur)
        if j is not None:
            x = i * step + j
            if x <= limit:
                return x
        if giant_chain is None:
            cur = oracle.mul(cur, giant_factor)
    return None


def solve_round(oracle, info: Dict[str, int]) -> int:
    one = info["one"]
    g = info["g"]
    h = info["h"]
    m = info["c_order"]
    bound = info["bound"]

    prefixes = [one]
    cur = one
    term = g
    for _ in range(m):
        cur = oracle.mul(cur, term)
        prefixes.append(cur)
        term = oracle.phi(term)
    period_elem = prefixes[m]

    for r in range(m):
        qmax = (bound - r) // m
        print(f"[remote] trying residue r={r} with qmax={qmax}", flush=True)
        target = h if prefixes[r] == one else oracle.mul(h, oracle.inv(prefixes[r]))
        q = bsgs_handle(oracle, period_elem, target, one, qmax, f"r={r}")
        if q is not None:
            return q * m + r
    raise RuntimeError("no solution found")


def run_selftest(rounds: int, p: int, bound: int, seed: Optional[int]) -> int:
    oracle = LocalOracle(p=p, bound=bound, seed=seed)
    for ridx in range(1, rounds + 1):
        oracle.start_round()
        info = {
            "one": oracle.one,
            "g": oracle.g,
            "c": oracle.c_handle,
            "h": oracle.h,
            "c_order": oracle.c_order,
            "bound": oracle.bound,
        }
        x = solve_round(oracle, info)
        ok = oracle.submit(x)
        print(
            f"[selftest] round={ridx} c_order={oracle.c_order} secret={oracle.last_secret} recovered={x} ok={ok}"
        )
        if not ok:
            return 1
    print("[selftest] all rounds passed")
    return 0


def run_remote(host: str, port: int) -> int:
    print(f"[remote] connecting to {host}:{port}...", flush=True)
    oracle = RemoteOracle(host, port)
    print("[remote] connected, waiting for first round...", flush=True)
    try:
        text = oracle.start_round()
        if text is None:
            print("connection closed before first round", file=sys.stderr)
            return 1
        if text.strip():
            print(text, end="" if text.endswith("\n") else "\n", flush=True)
        while True:
            if "flag{" in text or "bctf{" in text:
                print(text.strip())
                return 0
            if "Challenge failed." in text:
                print(text.strip(), file=sys.stderr)
                return 1
            info = parse_round(text)
            x = solve_round(oracle, info)
            print(
                f"[remote] c_order={info['c_order']} bound={info['bound']} solved_x={x}",
                flush=True,
            )
            text = oracle.submit(x)
            if text.strip():
                print(text, end="" if text.endswith("\n") else "\n", flush=True)
    finally:
        oracle.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    p_self = sub.add_parser("selftest")
    p_self.add_argument("--rounds", type=int, default=20)
    p_self.add_argument("--p", type=int, default=65537)
    p_self.add_argument("--bound", type=int, default=262144)
    p_self.add_argument("--seed", type=int)

    p_remote = sub.add_parser("remote")
    p_remote.add_argument("--host", default="sporadiclogarithms.opus4-7.b01le.rs")
    p_remote.add_argument("--port", type=int, default=8443)

    args = parser.parse_args()
    if args.mode == "selftest":
        return run_selftest(args.rounds, args.p, args.bound, args.seed)
    return run_remote(args.host, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
