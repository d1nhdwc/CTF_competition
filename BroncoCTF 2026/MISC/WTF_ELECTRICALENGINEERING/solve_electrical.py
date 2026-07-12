#!/usr/bin/env python3
import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decode the BroncoCTF Booth-decoder input sequence."
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="inputsequence.b",
        help="Path to inputsequence.b",
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")

    rows = [
        line.split()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip()
    ]

    decoded = []
    for row_no, row in enumerate(rows, 1):
        if len(row) != 8:
            raise SystemExit(
                f"Row {row_no}: expected 8 input vectors, got {len(row)}"
            )

        output_bits = []
        for vector in row:
            if len(vector) != 4 or any(bit not in "01" for bit in vector):
                raise SystemExit(
                    f"Row {row_no}: invalid 4-bit vector {vector!r}"
                )

            # Input order: neg_i, x_j, nx_(j-1), ot_i.
            neg_i, x_j, nx_j_minus_1, ot_i = map(int, vector)

            # Gate-level decoder:
            # nx_j = neg_i XOR x_j
            # zero_i is fixed to 0, so the output MUX remains enabled.
            # ot_i == 0 selects nx_(j-1); ot_i == 1 selects nx_j.
            nx_j = neg_i ^ x_j
            pp_ij = nx_j_minus_1 if ot_i == 0 else nx_j
            output_bits.append(str(pp_ij))

        byte_bits = "".join(output_bits)
        decoded.append(chr(int(byte_bits, 2)))
        print(f"{row_no:02d}: {byte_bits} -> {decoded[-1]!r}")

    print("\nFLAG:", "".join(decoded))


if __name__ == "__main__":
    main()
