#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass

from tinymt32 import _next_state, _temper


BALLS = [25, 48, 60, 75, 96, 120]
EMOJIS = "🟥🟧🟨🟩🟦🟪🟫⬜"
EVEN_LEAK_IDXS = (1, 2, 4, 5)
REMOTE_HOST = "streams.tamuctf.com"
REMOTE_PORT = 443
REMOTE_SSL = True
REMOTE_SNI = "tinyball"
POW_URL = "https://pwn.red/pow"
POW_SOLVER_PATH = "/tmp/tinyball_pow_solver.sh"
MAT1 = 0x8F7011EE
MAT2 = 0xFC78FF1F

FULL_LINE_RE = re.compile(r"^\s*│\s*((?:\d+\s+){5}\d+)\s*│\s*$")
CENSOR_LINE_RE = re.compile(r"^\s*│\s*([^\s].*[^\s])\s*│\s*$")


@dataclass
class ArchiveData:
    censored: list[list[int]]
    full: list[list[int]]


class LocalTube:
    def __init__(self, argv: list[str]):
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
        )
        self.buf = bytearray()

    def _read_some(self) -> bytes:
        return self.proc.stdout.read(1) or b""

    def recvuntil(self, needle: bytes, timeout: float = 10.0) -> bytes:
        deadline = time.time() + timeout
        while needle not in self.buf:
            if time.time() > deadline:
                raise TimeoutError(f"recvuntil timeout waiting for {needle!r}")
            chunk = self._read_some()
            if not chunk:
                break
            self.buf.extend(chunk)
        if needle not in self.buf:
            raise EOFError(f"stream closed before {needle!r}")
        idx = self.buf.index(needle) + len(needle)
        out = bytes(self.buf[:idx])
        del self.buf[:idx]
        return out

    def sendline(self, data: bytes) -> None:
        self.proc.stdin.write(data + b"\n")
        self.proc.stdin.flush()

    def recvall(self, timeout: float = 5.0) -> bytes:
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self._read_some()
            if not chunk:
                break
            self.buf.extend(chunk)
        tail = bytes(self.buf)
        self.buf.clear()
        rest = self.proc.stdout.read() or b""
        return tail + rest


class RemoteTube:
    def __init__(self, host: str, port: int, use_ssl: bool, sni: str | None):
        raw = socket.create_connection((host, port))
        if use_ssl:
            ctx = ssl._create_unverified_context()
            self.sock = ctx.wrap_socket(raw, server_hostname=sni or host)
        else:
            self.sock = raw
        self.buf = bytearray()

    def _read_some(self) -> bytes:
        return self.sock.recv(4096)

    def recvuntil(self, needle: bytes, timeout: float = 10.0) -> bytes:
        self.sock.settimeout(timeout)
        while needle not in self.buf:
            chunk = self._read_some()
            if not chunk:
                break
            self.buf.extend(chunk)
        if needle not in self.buf:
            raise EOFError(f"socket closed before {needle!r}")
        idx = self.buf.index(needle) + len(needle)
        out = bytes(self.buf[:idx])
        del self.buf[:idx]
        return out

    def sendline(self, data: bytes) -> None:
        self.sock.sendall(data + b"\n")

    def recvall(self, timeout: float = 5.0) -> bytes:
        self.sock.settimeout(timeout)
        while True:
            try:
                chunk = self._read_some()
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf.extend(chunk)
        out = bytes(self.buf)
        self.buf.clear()
        return out


def parse_archive(text: str) -> ArchiveData:
    in_archive = False
    censored: list[list[int]] = []
    full: list[list[int]] = []
    for line in text.splitlines():
        if "Archived Draws" in line:
            in_archive = True
            continue
        if not in_archive:
            continue
        if line.startswith("  └"):
            break

        m_full = FULL_LINE_RE.match(line)
        if m_full:
            full.append(list(map(int, m_full.group(1).split())))
            continue

        m_censor = CENSOR_LINE_RE.match(line)
        if not m_censor:
            continue
        payload = m_censor.group(1).replace(" ", "")
        if payload and all(ch in EMOJIS for ch in payload):
            censored.append([EMOJIS.index(ch) for ch in payload])

    if len(censored) != 17 or len(full) != 10:
        raise ValueError(f"unexpected archive layout: {len(censored)=} {len(full)=}")
    return ArchiveData(censored=censored, full=full)


def xor_words(a: list[int], b: list[int]) -> list[int]:
    return [x ^ y for x, y in zip(a, b)]


def shl(word: list[int], n: int) -> list[int]:
    return [0] * n + word[:-n]


def shr(word: list[int], n: int) -> list[int]:
    return word[n:] + [0] * n


def add_constmul(word: list[int], y0: int, const: int) -> list[int]:
    out = word[:]
    for i in range(32):
        if (const >> i) & 1:
            out[i] ^= y0
    return out


def init_mask_state() -> list[list[int]]:
    idx = 0
    words: list[list[int]] = []
    for w in range(4):
        arr = []
        max_bits = 31 if w == 0 else 32
        for bit in range(32):
            if bit < max_bits:
                arr.append(1 << idx)
                idx += 1
            else:
                arr.append(0)
        words.append(arr)
    return words


def next_mask_state(st: list[list[int]]) -> list[list[int]]:
    s0, s1, s2, s3 = st
    s0_masked = s0[:]
    s0_masked[31] = 0
    x = xor_words(xor_words(s0_masked, s1), s2)
    x = xor_words(x, shl(x, 1))
    y = xor_words(xor_words(s3, shr(s3, 1)), x)
    y0 = y[0]
    return [
        s1,
        add_constmul(s2, y0, MAT1),
        add_constmul(xor_words(x, shl(y, 10)), y0, MAT2),
        y,
    ]


def build_parity_rows(archive: ArchiveData) -> list[int]:
    rows: list[int] = []
    st = init_mask_state()
    for draw in archive.censored + archive.full:
        for idx in range(6):
            st = next_mask_state(st)
            if idx in EVEN_LEAK_IDXS:
                # For even moduli, output parity equals displayed residue parity.
                rows.append(st[3][0] | ((draw[idx] & 1) << 127))
    return rows


def rref(rows: list[int], nvars: int = 127) -> tuple[list[int], list[tuple[int, int]]]:
    rows = rows[:]
    pivots: list[tuple[int, int]] = []
    r = 0
    for c in range(nvars):
        pivot = None
        for i in range(r, len(rows)):
            if (rows[i] >> c) & 1:
                pivot = i
                break
        if pivot is None:
            continue
        rows[r], rows[pivot] = rows[pivot], rows[r]
        for i in range(len(rows)):
            if i != r and ((rows[i] >> c) & 1):
                rows[i] ^= rows[r]
        pivots.append((r, c))
        r += 1
        if r == len(rows):
            break
    return rows, pivots


def solve_affine_space(rows: list[int], pivots: list[tuple[int, int]], nvars: int = 127) -> tuple[list[int], list[list[int]]]:
    pivot_cols = {c: r for r, c in pivots}
    free_cols = [c for c in range(nvars) if c not in pivot_cols]

    def build_solution(free_assign: dict[int, int]) -> list[int]:
        sol = [0] * nvars
        for c, v in free_assign.items():
            sol[c] = v
        for r, c in reversed(pivots):
            row = rows[r]
            rhs = (row >> nvars) & 1
            acc = rhs
            mask = (row >> (c + 1)) & ((1 << (nvars - (c + 1))) - 1)
            j = c + 1
            while mask:
                if mask & 1:
                    acc ^= sol[j]
                mask >>= 1
                j += 1
            sol[c] = acc
        return sol

    particular = build_solution({})
    nullspace: list[list[int]] = []
    for free_col in free_cols:
        with_one = build_solution({free_col: 1})
        nullspace.append([a ^ b for a, b in zip(with_one, particular)])
    return particular, nullspace


def bits_to_state(bits: list[int]) -> tuple[int, int, int, int]:
    it = iter(bits)
    s0 = sum(next(it) << i for i in range(31))
    s1 = sum(next(it) << i for i in range(32))
    s2 = sum(next(it) << i for i in range(32))
    s3 = sum(next(it) << i for i in range(32))
    return s0, s1, s2, s3


def advance_state(state: tuple[int, int, int, int], outputs: int) -> tuple[int, int, int, int]:
    s0, s1, s2, s3 = state
    for _ in range(outputs):
        s0, s1, s2, s3 = _next_state(s0, s1, s2, s3)
    return s0, s1, s2, s3


def check_full_segment(
    state: tuple[int, int, int, int], full_draws: list[list[int]]
) -> tuple[bool, tuple[int, int, int, int]]:
    s0, s1, s2, s3 = state
    for draw in full_draws:
        for modulus, observed in zip(BALLS, draw):
            s0, s1, s2, s3 = _next_state(s0, s1, s2, s3)
            if _temper(s0, s2, s3) % modulus != observed:
                return False, (s0, s1, s2, s3)
    return True, (s0, s1, s2, s3)


def recover_full_segment_state(archive: ArchiveData) -> tuple[int, int, int, int]:
    rows = build_parity_rows(archive)
    rows, pivots = rref(rows)
    particular_bits, nullspace_bits = solve_affine_space(rows, pivots)

    print(f"[+] parity rank: {len(pivots)} / 127, nullity: {len(nullspace_bits)}", flush=True)

    particular_state = bits_to_state(particular_bits)
    particular_full = advance_state(particular_state, 17 * 6)
    basis_full = [advance_state(bits_to_state(vec), 17 * 6) for vec in nullspace_bits]

    cur = list(particular_full)
    prev_gray = 0
    search_start = time.time()

    for n in range(1 << len(basis_full)):
        gray = n ^ (n >> 1)
        if n:
            diff = gray ^ prev_gray
            bit = (diff & -diff).bit_length() - 1
            delta = basis_full[bit]
            cur[0] ^= delta[0]
            cur[1] ^= delta[1]
            cur[2] ^= delta[2]
            cur[3] ^= delta[3]
        prev_gray = gray

        ok, _ = check_full_segment(tuple(cur), archive.full)
        if ok:
            print(f"[+] affine search solved in {time.time() - search_start:.3f}s", flush=True)
            return tuple(cur)

    raise RuntimeError("no full-segment state survived the affine search")


def predict_answer(full_segment_state: tuple[int, int, int, int]) -> list[int]:
    s0, s1, s2, s3 = full_segment_state
    for _ in range(10):
        for _modulus in BALLS:
            s0, s1, s2, s3 = _next_state(s0, s1, s2, s3)

    # Skip today's hidden draw.
    for _modulus in BALLS:
        s0, s1, s2, s3 = _next_state(s0, s1, s2, s3)

    answer = []
    for modulus in BALLS:
        s0, s1, s2, s3 = _next_state(s0, s1, s2, s3)
        answer.append(_temper(s0, s2, s3) % modulus)
    return answer


def recv_pow_and_solve(io) -> None:
    first = io.recvuntil(b"\n", timeout=5)
    if b"proof of work" not in first.lower():
        raise RuntimeError("expected PoW banner from remote service")

    challenge = io.recvuntil(b"\n", timeout=5).decode().strip().split()[-1].rstrip(".")
    if not os.path.exists(POW_SOLVER_PATH):
        import requests

        pow_file = requests.get(POW_URL, timeout=10).text
        with open(POW_SOLVER_PATH, "w", encoding="utf-8") as fh:
            fh.write(pow_file)
        os.chmod(POW_SOLVER_PATH, 0o755)

    result = subprocess.run(["sh", POW_SOLVER_PATH, challenge], capture_output=True, text=True, check=True)
    io.recvuntil(b"solution: ", timeout=5)
    io.sendline(result.stdout.strip().encode())


def connect(args):
    if args.local:
        return LocalTube(["python3", "server.py"])

    io = RemoteTube(args.host, args.port, use_ssl=args.ssl, sni=args.sni if args.ssl else None)
    if args.pow:
        recv_pow_and_solve(io)
    return io


def solve_session(io) -> tuple[str, list[int]]:
    banner = io.recvuntil(b"Enter your prediction for tomorrow's draw:\n", timeout=10)
    text = banner.decode("utf-8", errors="replace")
    archive = parse_archive(text)
    print(f"[+] parsed archive: {len(archive.censored)} censored, {len(archive.full)} full", flush=True)
    full_segment_state = recover_full_segment_state(archive)
    answer = predict_answer(full_segment_state)
    io.sendline(b" ".join(str(x).encode() for x in answer))
    result = io.recvall(timeout=5).decode("utf-8", errors="replace")
    return text + result, answer


def main() -> None:
    parser = argparse.ArgumentParser(description="tinyball solver")
    parser.add_argument("--local", action="store_true", help="run against local server.py")
    parser.add_argument("--host", default=REMOTE_HOST)
    parser.add_argument("--port", type=int, default=REMOTE_PORT)
    parser.add_argument("--ssl", action=argparse.BooleanOptionalAction, default=REMOTE_SSL)
    parser.add_argument("--sni", default=REMOTE_SNI)
    parser.add_argument("--pow", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()

    io = connect(args)
    transcript, answer = solve_session(io)
    print(transcript, end="" if transcript.endswith("\n") else "\n")
    print(f"[+] submitted answer: {' '.join(map(str, answer))}")


if __name__ == "__main__":
    main()
