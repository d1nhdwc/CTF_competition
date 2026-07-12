#!/usr/bin/env python3
"""Hidden solver for: LEt's a GO! — concatenate .part_00 .. .part_49"""
import os, re, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    *[".."] * (len(__file__.split(os.sep)) - 1)))

def solve(start_dir: str) -> str:
    pattern = re.compile(r"^\.part_(\d+)$")
    parts: dict[int, str] = {}
    for dirpath, _, filenames in os.walk(start_dir):
        for fn in filenames:
            m = pattern.match(fn)
            if m:
                idx = int(m.group(1))
                if 0 <= idx <= 49:
                    with open(os.path.join(dirpath, fn)) as fh:
                        parts[idx] = fh.read()
    flag = "".join(parts[i] for i in sorted(parts))
    return flag

if __name__ == "__main__":
    start = sys.argv[1] if len(sys.argv) > 1 else "lego_bricks_challenge"
    print(solve(start))
