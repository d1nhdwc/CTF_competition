#!/usr/bin/env python3
"""
Generic TinyMT32 state/seed recovery helper for CTF challenges where the service
leaks either full outputs or RGB-colour projections of past outputs.

This is NOT tied to a specific remote protocol.  It is meant to be dropped into
solver-template.py once the challenge-specific parsing is known.

Supported observation modes:
  - raw32              : full 32-bit outputs are known.
  - low24              : observed value = output & 0xFFFFFF.
  - high24             : observed value = output >> 8.
  - bytes012           : RGB = bytes [0,1,2] from little-endian output.
  - bytes123           : RGB = bytes [1,2,3] from little-endian output.
  - bytes210           : RGB = bytes [2,1,0] from little-endian output.
  - bytes321           : RGB = bytes [3,2,1] from little-endian output.

The solver models the TinyMT32 state *after* initialization / preloop.
If you prefer to recover the 32-bit seed directly, add `recover_seed=True`.

Practical use:
  1) parse archive squares into integers (0..0xFFFFFF) or full outputs
  2) call recover_candidates(...)
  3) for each candidate state, step TinyMT32 forward and interact with service

Requirements: z3-solver
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple

try:
    from z3 import BitVec, BitVecVal, If, LShR, Solver, Or, sat
except ImportError as exc:
    raise SystemExit("z3-solver is required: python3 -m pip install z3-solver") from exc

MASK32 = 0xFFFFFFFF
MAT1 = 0x8F7011EE
MAT2 = 0xFC78FF1F
TMAT = 0x3793FDFF


# ---------------------------------------------------------------------------
# Concrete TinyMT32
# ---------------------------------------------------------------------------

def init_from_seed(seed: int) -> list[int]:
    seed &= MASK32
    st = [seed, MAT1, MAT2, TMAT]
    for i in range(1, 8):
        x = st[(i - 1) & 3]
        st[i & 3] ^= (i + 1812433253 * (x ^ (x >> 30))) & MASK32
        st[i & 3] &= MASK32
    for _ in range(8):
        st = next_state(st)
    return st


def next_state(st: Sequence[int]) -> list[int]:
    s0, s1, s2, s3 = [x & MASK32 for x in st]
    x = (s0 & 0x7FFFFFFF) ^ s1 ^ s2
    x ^= (x << 1) & MASK32
    y = s3 ^ (s3 >> 1) ^ x
    ns0 = s1
    ns1 = s2
    ns2 = (x ^ ((y << 10) & MASK32)) & MASK32
    ns3 = y & MASK32
    if y & 1:
        ns1 ^= MAT1
        ns2 ^= MAT2
    return [ns0 & MASK32, ns1 & MASK32, ns2 & MASK32, ns3 & MASK32]


def temper(st: Sequence[int]) -> int:
    s0, _, s2, s3 = [x & MASK32 for x in st]
    t1 = (s0 + (s2 >> 8)) & MASK32
    t0 = s3 ^ t1
    if t1 & 1:
        t0 ^= TMAT
    return t0 & MASK32


def gen_u32(st: Sequence[int]) -> tuple[list[int], int]:
    st2 = next_state(st)
    return st2, temper(st2)


def inv_xor_lshift1(v: int) -> int:
    """Invert x -> x ^ (x << 1) over 32-bit words."""
    v &= MASK32
    x = 0
    prev = 0
    for i in range(32):
        bit = ((v >> i) & 1) ^ prev
        x |= bit << i
        prev = bit
    return x & MASK32


def inv_xor_rshift1(v: int) -> int:
    """Invert x -> x ^ (x >> 1) over 32-bit words."""
    v &= MASK32
    x = 0
    nxt = 0
    for i in range(31, -1, -1):
        bit = ((v >> i) & 1) ^ nxt
        x |= bit << i
        nxt = bit
    return x & MASK32


def prev_state_from_next(next_st: Sequence[int], prev_output: int) -> list[int]:
    """
    Recover previous state from the next state and the previous *full* 32-bit output.
    This is useful for local reverse-walking once at least one full output is known.
    """
    a1, b1, c1, d1 = [x & MASK32 for x in next_st]
    cond = d1 & 1
    prev1 = a1
    prev2 = b1 ^ (MAT1 if cond else 0)
    x = c1 ^ ((d1 << 10) & MASK32) ^ (MAT2 if cond else 0)
    z = inv_xor_lshift1(x)
    prev0_low31 = (z ^ prev1 ^ prev2) & 0x7FFFFFFF
    prev3 = inv_xor_rshift1(d1 ^ x)

    # top bit of prev0 is the only missing bit from backward inversion;
    # full output disambiguates it immediately.
    cands = []
    for msb in (0, 1):
        prev0 = prev0_low31 | (msb << 31)
        st = [prev0, prev1, prev2, prev3]
        if temper(st) == (prev_output & MASK32):
            cands.append(st)
    if len(cands) != 1:
        raise ValueError(f"expected unique predecessor, got {len(cands)}")
    return cands[0]


# ---------------------------------------------------------------------------
# Symbolic TinyMT32
# ---------------------------------------------------------------------------

def s_const(v: int):
    return BitVecVal(v & MASK32, 32)


def s_next_state(st):
    s0, s1, s2, s3 = st
    x = (s0 & s_const(0x7FFFFFFF)) ^ s1 ^ s2
    x = x ^ ((x << 1) & s_const(MASK32))
    y = s3 ^ LShR(s3, 1) ^ x
    ns0 = s1
    ns1 = If((y & 1) == 1, s2 ^ s_const(MAT1), s2)
    ns2_0 = x ^ ((y << 10) & s_const(MASK32))
    ns2 = If((y & 1) == 1, ns2_0 ^ s_const(MAT2), ns2_0)
    ns3 = y
    return [ns0, ns1, ns2, ns3]


def s_temper(st):
    s0, _, s2, s3 = st
    t1 = s0 + LShR(s2, 8)
    t0 = s3 ^ t1
    return If((t1 & 1) == 1, t0 ^ s_const(TMAT), t0)


def s_init_from_seed(seed):
    st = [seed, s_const(MAT1), s_const(MAT2), s_const(TMAT)]
    for i in range(1, 8):
        prev = st[(i - 1) & 3]
        upd = s_const(i) + s_const(1812433253) * (prev ^ LShR(prev, 30))
        st[i & 3] = st[i & 3] ^ upd
    for _ in range(8):
        st = s_next_state(st)
    return st


# ---------------------------------------------------------------------------
# Leak models
# ---------------------------------------------------------------------------

def output_to_rgb_modes(out: int) -> dict[str, int]:
    out &= MASK32
    b0 = out & 0xFF
    b1 = (out >> 8) & 0xFF
    b2 = (out >> 16) & 0xFF
    b3 = (out >> 24) & 0xFF
    return {
        "raw32": out,
        "low24": out & 0xFFFFFF,
        "high24": (out >> 8) & 0xFFFFFF,
        "bytes012": b0 | (b1 << 8) | (b2 << 16),
        "bytes123": b1 | (b2 << 8) | (b3 << 16),
        "bytes210": b2 | (b1 << 8) | (b0 << 16),
        "bytes321": b3 | (b2 << 8) | (b1 << 16),
    }


def add_observation_constraint(slv: Solver, sym_out, obs: int, mode: str) -> None:
    obs &= MASK32
    if mode == "raw32":
        slv.add(sym_out == s_const(obs))
        return
    if mode == "low24":
        slv.add((sym_out & s_const(0xFFFFFF)) == s_const(obs & 0xFFFFFF))
        return
    if mode == "high24":
        slv.add(LShR(sym_out, 8) == s_const(obs & 0xFFFFFF))
        return

    def byte(expr, idx: int):
        return LShR(expr, idx * 8) & s_const(0xFF)

    r = obs & 0xFF
    g = (obs >> 8) & 0xFF
    b = (obs >> 16) & 0xFF

    if mode == "bytes012":
        slv.add(byte(sym_out, 0) == s_const(r))
        slv.add(byte(sym_out, 1) == s_const(g))
        slv.add(byte(sym_out, 2) == s_const(b))
        return
    if mode == "bytes123":
        slv.add(byte(sym_out, 1) == s_const(r))
        slv.add(byte(sym_out, 2) == s_const(g))
        slv.add(byte(sym_out, 3) == s_const(b))
        return
    if mode == "bytes210":
        slv.add(byte(sym_out, 2) == s_const(r))
        slv.add(byte(sym_out, 1) == s_const(g))
        slv.add(byte(sym_out, 0) == s_const(b))
        return
    if mode == "bytes321":
        slv.add(byte(sym_out, 3) == s_const(r))
        slv.add(byte(sym_out, 2) == s_const(g))
        slv.add(byte(sym_out, 1) == s_const(b))
        return

    raise ValueError(f"unsupported mode: {mode}")


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    mode: str
    state: tuple[int, int, int, int]
    seed: int | None


def recover_candidates(observations: Sequence[int], modes: Sequence[str], recover_seed: bool = False,
                       max_candidates_per_mode: int = 3, timeout_ms: int = 0) -> list[Candidate]:
    results: list[Candidate] = []
    for mode in modes:
        slv = Solver()
        if timeout_ms:
            slv.set(timeout=timeout_ms)

        if recover_seed:
            seed = BitVec(f"seed_{mode}", 32)
            st = s_init_from_seed(seed)
            model_vars = [seed]
        else:
            st = [BitVec(f"{mode}_s{i}", 32) for i in range(4)]
            seed = None
            model_vars = st[:]

        cur = st
        for obs in observations:
            cur = s_next_state(cur)
            sym_out = s_temper(cur)
            add_observation_constraint(slv, sym_out, obs, mode)

        found = 0
        while found < max_candidates_per_mode and slv.check() == sat:
            m = slv.model()
            if recover_seed:
                seed_val = m[seed].as_long()
                state_val = tuple(init_from_seed(seed_val))
                results.append(Candidate(mode=mode, state=state_val, seed=seed_val))
                slv.add(seed != s_const(seed_val))
            else:
                state_val = tuple(m[v].as_long() for v in model_vars)
                results.append(Candidate(mode=mode, state=state_val, seed=None))
                slv.add(Or(*[model_vars[i] != s_const(state_val[i]) for i in range(4)]))
            found += 1
    return results


# ---------------------------------------------------------------------------
# Parsers / CLI helpers
# ---------------------------------------------------------------------------

ANSI_RGB_RE = re.compile(r"(?:38|48);2;(\d+);(\d+);(\d+)")
HEX_RE = re.compile(r"#?([0-9a-fA-F]{6}|[0-9a-fA-F]{8})")


def parse_hex_list(items: Iterable[str]) -> list[int]:
    out = []
    for x in items:
        x = x.strip().lower()
        if x.startswith("0x"):
            out.append(int(x, 16))
        else:
            out.append(int(x, 16))
    return out


def parse_ansi_rgb(text: str) -> list[int]:
    vals = []
    for m in ANSI_RGB_RE.finditer(text):
        r, g, b = map(int, m.groups())
        vals.append((r & 0xFF) | ((g & 0xFF) << 8) | ((b & 0xFF) << 16))
    return vals


def parse_hex_colors(text: str) -> list[int]:
    vals = []
    for m in HEX_RE.finditer(text):
        hx = m.group(1)
        if len(hx) == 8:
            hx = hx[:6]
        vals.append(int(hx, 16))
    return vals


def main() -> None:
    ap = argparse.ArgumentParser(description="Generic TinyMT32 recovery helper")
    ap.add_argument("--mode", action="append", dest="modes", default=[],
                    help="leak mode to try (can repeat)")
    ap.add_argument("--obs", nargs="*", default=[], help="observations as hex values")
    ap.add_argument("--obs-file", help="read observations from file; parser auto-detect is not automatic")
    ap.add_argument("--ansi-rgb", action="store_true", help="parse obs-file as ANSI RGB escapes")
    ap.add_argument("--hex-colors", action="store_true", help="parse obs-file for #RRGGBB values")
    ap.add_argument("--recover-seed", action="store_true", help="solve for 32-bit seed instead of post-init state")
    ap.add_argument("--timeout-ms", type=int, default=0)
    ap.add_argument("--max-cands", type=int, default=3)
    args = ap.parse_args()

    modes = args.modes or ["low24", "high24", "bytes012", "bytes123"]
    obs: list[int] = []
    if args.obs:
        obs.extend(parse_hex_list(args.obs))
    if args.obs_file:
        data = open(args.obs_file, "r", encoding="utf-8", errors="ignore").read()
        if args.ansi_rgb:
            obs.extend(parse_ansi_rgb(data))
        elif args.hex_colors:
            obs.extend(parse_hex_colors(data))
        else:
            raise SystemExit("choose --ansi-rgb or --hex-colors with --obs-file")

    if not obs:
        raise SystemExit("no observations supplied")

    cands = recover_candidates(obs, modes=modes, recover_seed=args.recover_seed,
                               max_candidates_per_mode=args.max_cands,
                               timeout_ms=args.timeout_ms)
    if not cands:
        print("no candidates")
        return

    for idx, cand in enumerate(cands, 1):
        s0, s1, s2, s3 = cand.state
        print(f"[{idx}] mode={cand.mode} seed={cand.seed!r} state="
              f"({s0:#010x}, {s1:#010x}, {s2:#010x}, {s3:#010x})")
        st = list(cand.state)
        preview = []
        for _ in range(5):
            st, out = gen_u32(st)
            preview.append(f"{out:#010x}")
        print("    next outputs:", " ".join(preview))


if __name__ == "__main__":
    main()
