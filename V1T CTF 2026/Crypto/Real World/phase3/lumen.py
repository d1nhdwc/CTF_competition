from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


LANE = 16
STATE_LANES = 16
INIT_ROUNDS = 32
FINAL_ROUNDS = 32

C0 = 0x243F6A8885A308D313198A2E03707344
C1 = 0xA4093822299F31D0082EFA98EC4E6C89
MASK128 = (1 << 128) - 1

SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


def _blocks(buf: bytes) -> list[int]:
    if len(buf) % LANE:
        buf += b"\x00" * (LANE - len(buf) % LANE)
    return [int.from_bytes(buf[i:i + LANE], "big") for i in range(0, len(buf), LANE)]


def _chunks(buf: bytes):
    for i in range(0, len(buf), LANE):
        yield buf[i:i + LANE]


def _pack(words: list[int], size: int | None = None) -> bytes:
    out = b"".join((w & MASK128).to_bytes(LANE, "big") for w in words)
    return out if size is None else out[:size]


def _xtime(x: int) -> int:
    x <<= 1
    return (x ^ 0x11B) & 0xFF if x & 0x100 else x


def _mix_column(col: list[int]) -> list[int]:
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    return [
        col[0] ^ t ^ _xtime(col[0] ^ col[1]),
        col[1] ^ t ^ _xtime(col[1] ^ col[2]),
        col[2] ^ t ^ _xtime(col[2] ^ col[3]),
        col[3] ^ t ^ _xtime(col[3] ^ col[0]),
    ]


def _aesenc(x: int, rk: int) -> int:
    s = [SBOX[b] for b in (x & MASK128).to_bytes(LANE, "big")]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    for c in range(4):
        s[c * 4:c * 4 + 4] = _mix_column(s[c * 4:c * 4 + 4])
    return int.from_bytes(bytes(s), "big") ^ rk


def _keys(material: bytes) -> tuple[int, int]:
    if len(material) != 32:
        raise ValueError("material must contain exactly 32 bytes")
    return (
        int.from_bytes(material[:16], "big"),
        int.from_bytes(material[16:], "big"),
    )


def _stream(state: list[int]) -> int:
    return _aesenc(state[0] ^ state[1], state[9]) ^ state[13]


def _update(state: list[int], block: int) -> int:
    out = _stream(state)
    fresh = (
        _aesenc(state[0], state[1])
        ^ state[3]
        ^ state[9]
        ^ _aesenc(state[13], state[0])
        ^ block
    ) & MASK128
    state[:] = state[1:] + [fresh]
    return out


def _state(material: bytes, tint: bytes) -> list[int]:
    if len(tint) != LANE:
        raise ValueError("tint must contain exactly 16 bytes")

    k0, k1 = _keys(material)
    n = int.from_bytes(tint, "big")
    state = [
        C0, k0, n, C1,
        k1, n ^ k0, C0 ^ k1, 0,
        k0 ^ C1, n ^ C0, k1 ^ C0, 0,
        C1, k0 ^ k1, n ^ C1, C0 ^ C1,
    ]
    for r in range(INIT_ROUNDS):
        _update(state, C0 ^ C1 ^ r)
    state[9] ^= k0
    state[13] ^= k1
    return state


def _finalize(state: list[int], ad_len: int, msg_len: int) -> bytes:
    lens = ((ad_len * 8) << 64) ^ (msg_len * 8)
    state[9] ^= lens
    state[13] ^= ((lens << 17) | (lens >> 111)) & MASK128
    for r in range(FINAL_ROUNDS):
        _update(state, lens ^ C0 ^ r)
    tag = 0
    for lane in state:
        tag ^= lane
    return tag.to_bytes(LANE, "big")


@dataclass(frozen=True)
class Packet:
    body: bytes
    check: bytes


def seal(material: bytes, tint: bytes, plain: bytes, associated_data: bytes = b"") -> Packet:
    state = _state(material, tint)
    for block in _blocks(associated_data):
        _update(state, block)

    out = bytearray()
    for chunk in _chunks(plain):
        padded = chunk + b"\x00" * (LANE - len(chunk))
        block = int.from_bytes(padded, "big")
        glow = _stream(state).to_bytes(LANE, "big")
        out.extend(bytes(a ^ b for a, b in zip(chunk, glow)))
        _update(state, block)
    return Packet(bytes(out), _finalize(state, len(associated_data), len(plain)))


def open_packet(material: bytes, tint: bytes, body: bytes, check: bytes, associated_data: bytes = b"") -> bytes:
    state = _state(material, tint)
    for block in _blocks(associated_data):
        _update(state, block)

    out = bytearray()
    for chunk in _chunks(body):
        glow = _stream(state).to_bytes(LANE, "big")
        plain = bytes(a ^ b for a, b in zip(chunk, glow))
        out.extend(plain)
        padded = plain + b"\x00" * (LANE - len(plain))
        _update(state, int.from_bytes(padded, "big"))
    tag = _finalize(state, len(associated_data), len(body))
    if tag != check:
        raise ValueError("the picture does not balance")
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="watch the last lantern settle")
    parser.add_argument("map", nargs="?", default="phase3.json")
    parser.add_argument("material", nargs="?")
    parser.add_argument("tint", nargs="?")
    args = parser.parse_args()

    chart = Path(args.map)
    data = json.loads(chart.read_text())
    if args.material is None or args.tint is None:
        parser.error("material and tint must be provided as hex strings")

    plain = open_packet(
        bytes.fromhex(args.material),
        bytes.fromhex(args.tint),
        (chart.parent / data["blob"]).read_bytes(),
        bytes.fromhex(data["mark"]),
    )
    print(plain.decode(errors="replace"))


if __name__ == "__main__":
    main()
