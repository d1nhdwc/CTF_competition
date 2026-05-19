import base64
import subprocess
import sys
from itertools import product


KEY_HEX = (b"lasagna!" * 2).hex()
ALPHABET = "".join(chr(i) for i in range(32, 127))


def aes_block_for_char(ch: str) -> bytes:
    return subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", KEY_HEX, "-nopad", "-nosalt"],
        input=bytes([ord(ch)]) * 16,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout


def recover_flag(output_bytes: bytes) -> str | None:
    length = len(output_bytes)
    blocks = {ch: aes_block_for_char(ch) for ch in ALPHABET}

    first_byte_lookup: dict[int, list[str]] = {}
    for ch, block in blocks.items():
        first_byte_lookup.setdefault(block[0], []).append(ch)

    prefix = list("bbccttff{{")

    def extend(state: list[str], start_index: int) -> str | None:
        stack: list[tuple[list[str], int]] = [(state[:], start_index)]
        while stack:
            doubled_flag, index = stack.pop()
            ok = True

            while index < length:
                needed = output_bytes[index]
                for offset in range(1, 16):
                    needed ^= blocks[doubled_flag[index - offset]][offset]

                options = first_byte_lookup.get(needed, [])
                if index % 2 == 1:
                    if doubled_flag[index - 1] not in options:
                        ok = False
                        break
                    if index == len(doubled_flag):
                        doubled_flag.append(doubled_flag[index - 1])
                    index += 1
                    continue

                if not options:
                    ok = False
                    break

                for ch in options[1:]:
                    stack.append((doubled_flag + [ch], index + 1))

                if index == len(doubled_flag):
                    doubled_flag.append(options[0])
                index += 1

            if not ok or len(doubled_flag) != length:
                continue

            for i in range(0, length, 2):
                if doubled_flag[i] != doubled_flag[i + 1]:
                    ok = False
                    break
            if not ok:
                continue

            for index in range(length):
                value = 0
                for offset in range(16):
                    value ^= blocks[doubled_flag[(index - offset) % length]][offset]
                if value != output_bytes[index]:
                    ok = False
                    break

            if ok:
                return "".join(doubled_flag[::2])

        return None

    for initial in product(ALPHABET, repeat=3):
        doubled_flag = prefix + [
            initial[0],
            initial[0],
            initial[1],
            initial[1],
            initial[2],
            initial[2],
        ]

        valid = True
        for index in range(15, length):
            needed = output_bytes[index]
            for offset in range(1, 16):
                needed ^= blocks[doubled_flag[index - offset]][offset]

            options = first_byte_lookup.get(needed, [])
            if index % 2 == 1:
                if doubled_flag[index - 1] not in options:
                    valid = False
                    break
                if index == len(doubled_flag):
                    doubled_flag.append(doubled_flag[index - 1])
                continue

            if not options:
                valid = False
                break

            if len(options) > 1:
                result = extend(doubled_flag + [options[0]], index + 1)
                if result is not None:
                    return result
                valid = False
                break

            if index == len(doubled_flag):
                doubled_flag.append(options[0])

        if valid:
            result = extend(doubled_flag, len(doubled_flag))
            if result is not None:
                return result

    return None


def main() -> int:
    output_bytes = base64.b64decode(open("output.txt", "rb").read().strip())
    flag = recover_flag(output_bytes)
    if flag is None:
        return 1
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
