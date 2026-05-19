from pathlib import Path

from Crypto.Util.number import long_to_bytes

M = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f


def encrypt(val, key):
    amp = val
    p = M

    prev = 1
    current = amp
    for _ in range(key - 1):
        new_val = (2 * amp * current - prev) % p
        prev = current
        current = new_val
    return current

flag_bytes = ("flag.enc").read_bytes()

base_val = 0x1337C0DE
frequency_key = 10**25

secret = encrypt(base_val, frequency_key)

encrypted = bytes([a ^ b for a, b in zip(flag_bytes, long_to_bytes(secret))])

print(encrypted)
