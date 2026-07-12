#!/usr/bin/env python3
import re
import sys
from pathlib import Path

MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
]
DAYS = [
    "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday", "Sunday",
]
AREAS = ["Asia", "Africa", "the Americas", "Europe", "Australia"]

LINE_RE = re.compile(
    r"born in (" + "|".join(MONTHS) + r")\.\.\. "
    r"on a (" + "|".join(DAYS) + r"), "
    r"in (" + "|".join(AREAS) + r")"
)


def decode_guesses(text: str) -> list[int]:
    outputs = []

    for month, day, area in LINE_RE.findall(text):
        residues = (
            MONTHS.index(month),
            DAYS.index(day),
            AREAS.index(area),
        )

        candidates = [
            x for x in range(256)
            if x % 12 == residues[0]
            and x % 7 == residues[1]
            and x % 5 == residues[2]
        ]

        if len(candidates) != 1:
            raise ValueError(
                f"Guess does not uniquely identify a byte: "
                f"{month}, {day}, {area}"
            )

        outputs.append(candidates[0])

    if not outputs:
        raise ValueError("No birthday guesses found")

    return outputs


def find_flag_length(outputs: list[int]) -> int:
    # Once a state position is revisited after N calls, its old value is
    # output[t-N]. Therefore:
    #
    # output[t+1] = 2*output[t] - output[t-N] (mod 256)
    #
    possible = []

    for n in range(1, len(outputs) - 1):
        if all(
            outputs[t + 1] == (2 * outputs[t] - outputs[t - n]) % 256
            for t in range(n, len(outputs) - 1)
        ):
            possible.append(n)

    if len(possible) != 1:
        raise ValueError(f"Could not uniquely determine flag length: {possible}")

    return possible[0]


def rotations(data: bytes):
    for i in range(len(data)):
        yield data[i:] + data[:i]


def recover_flag(outputs: list[int], n: int) -> bytes:
    # During the first cycle, the overwritten byte is:
    #
    # old = 2*output[t] - output[t+1] (mod 256)
    #
    # These bytes appear in schedule order. The schedule is only a cyclic
    # rotation of the original indices, optionally reversed.
    schedule_order = bytes(
        (2 * outputs[t] - outputs[t + 1]) % 256
        for t in range(n)
    )

    candidates = list(rotations(schedule_order))
    candidates += list(rotations(schedule_order[::-1]))

    flag_re = re.compile(rb"bronco\{[ -~]+\}\r?\n?$")
    matches = [candidate for candidate in candidates if flag_re.fullmatch(candidate)]

    if len(matches) != 1:
        readable = [
            candidate for candidate in candidates
            if all(byte in b"\r\n\t" or 32 <= byte <= 126 for byte in candidate)
        ]
        raise ValueError(
            f"Expected exactly one flag candidate, got {len(matches)}.\n"
            f"Readable candidates: {readable}"
        )

    return matches[0].rstrip(b"\r\n")


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "results.txt")
    outputs = decode_guesses(path.read_text())
    n = find_flag_length(outputs)
    flag = recover_flag(outputs, n)

    print(f"[+] Decoded outputs: {len(outputs)}")
    print(f"[+] Flag length: {n}")
    print(f"[+] Flag: {flag.decode()}")


if __name__ == "__main__":
    main()