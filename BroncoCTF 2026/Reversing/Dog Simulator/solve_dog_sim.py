#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path

MASK = 0xFFFFFFFF
FNV_PRIME = 0x01000193
FNV_OFFSET = 0x811C9DC5
TARGET_SPEAK_HASH = 0x9F58D866
TARGET_ROUTINE_HASH = 0x740A8A98
TARGET_STATE_HASH = 0xF5D38524

# A valid 12-letter lowercase FNV-1a preimage for TARGET_SPEAK_HASH.
FIRST_COMMAND = "zmsixlbcpfns"
SECOND_COMMAND = "gremlin"
SEQUENCE = ("fetch", "sit", "bark", "speak1", "eat", "speak2")


def u32(value: int) -> int:
    return value & MASK


def ror32(value: int, amount: int) -> int:
    value &= MASK
    return ((value >> amount) | (value << (32 - amount))) & MASK


def mix32(value: int) -> int:
    value &= MASK
    value ^= value >> 16
    value = u32(value * 0x7FEB352D)
    value ^= value >> 15
    value = u32(value * 0x846CA68B)
    value ^= value >> 16
    return u32(value)


def normalized_fnv(command: str) -> tuple[int, int, str]:
    """Match the binary: lowercase and hash ASCII alphabetic characters only."""
    state = FNV_OFFSET
    normalized = []
    for char in command:
        if "A" <= char <= "Z" or "a" <= char <= "z":
            char = char.lower()
            normalized.append(char)
            state ^= ord(char)
            state = u32(state * FNV_PRIME)
    text = "".join(normalized)
    return state, len(text), text


def mood_after(mood: int, action: str) -> int:
    transitions = {
        "bark":  (1, 2, 2, 0),
        "fetch": (0, 1, 2, 1),
        "sit":   (0, 0, 1, 3),
        "eat":   (3, 0, 0, 3),
        "speak": (0, 1, 2, 3),
    }
    return transitions[action][mood]


def combo_after(combo: int, action: str, speak_hash: int | None = None) -> int:
    if action == "fetch":
        return 4 if combo == 4 else 1
    if action == "sit":
        return 2 if combo == 1 else (4 if combo == 4 else 0)
    if action == "bark":
        return 3 if combo == 2 else (4 if combo == 4 else 0)
    if action == "eat":
        return 4 if combo == 4 else 0
    if action == "speak":
        if speak_hash == TARGET_SPEAK_HASH:
            return 4 if combo in (3, 4) else 0
        return 4 if combo == 4 else 0
    raise ValueError(f"unsupported action: {action}")


def simulate() -> dict[str, int]:
    score = 0
    bond = 12
    energy = 40
    mood = 0
    combo = 0
    state_hash = 0x13579BDF
    routine_hash = 0xBADC0FFE
    total_letters = 0

    action_number = {"bark": 1, "fetch": 2, "sit": 3, "eat": 4, "speak": 6}
    score_delta = {"bark": 10, "fetch": 20, "sit": 15, "eat": 10, "speak": 0}
    bond_delta = {"bark": 2, "fetch": 5, "sit": 4, "eat": 1, "speak": 3}
    energy_delta = {"bark": -4, "fetch": -8, "sit": -2, "speak": -1}

    for item in SEQUENCE:
        action = "speak" if item.startswith("speak") else item
        speak_hash = None

        if item == "speak1":
            speak_hash, letters, _ = normalized_fnv(FIRST_COMMAND)
            assert speak_hash == TARGET_SPEAK_HASH and letters == 12
            total_letters += letters
            routine_hash = mix32(routine_hash ^ speak_hash ^ (letters * 0x83))
        elif item == "speak2":
            speak_hash, letters, normalized = normalized_fnv(SECOND_COMMAND)
            assert normalized == "gremlin" and letters == 7
            total_letters += letters
            routine_hash = mix32(routine_hash ^ speak_hash ^ (letters * 0x83))

        score += score_delta[action]
        bond += bond_delta[action]
        if action == "eat":
            energy = 60 if energy > 48 else energy + 12
        else:
            energy += energy_delta[action]

        mood = mood_after(mood, action)
        combo = combo_after(combo, action, speak_hash)

        mood_term = u32(0xA5A5A5A5 + mood * 0x11111111)
        energy_term = u32((energy & 0xFF) * 0x045D9F3B)
        state_hash = mix32(
            u32(ror32(state_hash ^ (action_number[action] * 0x9E37), 27) + mood_term)
            ^ energy_term
        )

    result = {
        "score": score,
        "bond": bond,
        "energy": energy,
        "mood": mood,
        "combo": combo,
        "letters": total_letters,
        "routine_hash": routine_hash,
        "state_hash": state_hash,
    }
    assert score == 55
    assert bond > 24
    assert energy > 20
    assert mood != 2
    assert combo == 4
    assert total_letters == 19
    assert routine_hash == TARGET_ROUTINE_HASH
    assert state_hash == TARGET_STATE_HASH
    return result


def read_u32x4(blob: bytes, offset: int) -> list[int]:
    return list(struct.unpack_from("<4I", blob, offset))


def read_i32x4(blob: bytes, offset: int) -> list[int]:
    return list(struct.unpack_from("<4i", blob, offset))


def ushl_u32(values: list[int], shifts: list[int]) -> list[int]:
    output = []
    for value, shift in zip(values, shifts):
        if shift >= 0:
            output.append(0 if shift >= 32 else u32(value << shift))
        else:
            amount = -shift
            output.append(0 if amount >= 32 else value >> amount)
    return output


def vector_or(left: list[int], right: list[int]) -> list[int]:
    return [u32(a | b) for a, b in zip(left, right)]


def vector_xor(left: list[int], right: list[int]) -> list[int]:
    return [u32(a ^ b) for a, b in zip(left, right)]


def vector_add(left: list[int], right: list[int]) -> list[int]:
    return [u32(a + b) for a, b in zip(left, right)]


def decode_block(blob: bytes, base: int, mask_offset: int, key: int) -> bytes:
    key_vector = [key] * 4
    first = vector_xor(read_u32x4(blob, base), key_vector)
    second = vector_xor(read_u32x4(blob, base + 0x10), key_vector)

    rotated_second = vector_or(
        ushl_u32(second, read_i32x4(blob, base + 0x20)),
        ushl_u32(second, read_i32x4(blob, base + 0x30)),
    )
    rotated_first = vector_or(
        ushl_u32(first, read_i32x4(blob, base + 0x40)),
        ushl_u32(first, read_i32x4(blob, base + 0x50)),
    )

    first_part = vector_xor(rotated_first, read_u32x4(blob, base + 0x60))
    second_part = vector_xor(rotated_second, read_u32x4(blob, base + 0x70))
    second_part = vector_add(second_part, read_u32x4(blob, base + 0x80))
    first_part = vector_add(first_part, read_u32x4(blob, base + 0x90))

    packed = bytes([mix32(value) & 0xFF for value in first_part])
    packed += bytes([mix32(value) & 0xFF for value in second_part])
    mask = blob[mask_offset:mask_offset + 8]
    return bytes(a ^ b for a, b in zip(packed, mask))


def recover_flag(binary_path: Path) -> str:
    blob = binary_path.read_bytes()
    if blob[:4] != bytes.fromhex("cffaedfe"):
        raise ValueError("input is not the expected 64-bit little-endian Mach-O")

    state = simulate()
    key_material = (
        state["energy"] * 13
        ^ state["bond"] * 31
        ^ state["mood"] * 0x13579BDF
        ^ 0x510211DB
    )
    key = mix32(key_material)

    # __TEXT starts at file offset 0, so VM offsets 0x1420 etc. equal file offsets.
    plaintext = b"".join(
        (
            decode_block(blob, 0x1420, 0x1600, key),
            decode_block(blob, 0x14C0, 0x1608, key),
            decode_block(blob, 0x1560, 0x1610, key),
        )
    )
    return plaintext.rstrip(b"\0").decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Static solver for dog-sim-mac")
    parser.add_argument("binary", nargs="?", default="dog-sim-mac")
    args = parser.parse_args()

    path = Path(args.binary)
    flag = recover_flag(path)
    print("Actions:")
    print("  Day 1: 2  (Fetch)")
    print("  Day 2: 3  (Sit)")
    print("  Day 3: 1  (Bark)")
    print(f"  Day 4: 6, command = {FIRST_COMMAND}")
    print("  Day 5: 4  (Eat)")
    print(f"  Day 6: 6, command = {SECOND_COMMAND}")
    print(f"Flag: {flag}")


if __name__ == "__main__":
    main()
