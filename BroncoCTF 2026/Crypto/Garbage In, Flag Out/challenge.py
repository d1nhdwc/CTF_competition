import random
import string

FLAG = [REDACTED]
N = len(FLAG)


def scramble(key: bytes):
    nums = []
    for k in key:
        num = 0
        for i in range(8):
            num |= ((k & (1 << i)) >> i) << (7 - i)
        nums.append(num)
    return bytes(nums)


def block_encrypt(key: bytes, string: str):
    keys = [key]

    while len(string) - sum(map(len, keys)) > 0:
        key_ext = []
        for element in keys[-1]:
            newkey = 0
            for i in range(4):
                sub = (element >> (2 * i)) & 3
                sub = (sub & 1) ^ (sub >> 1)
                newkey += sub << (7 - i)

            newkey += random.getrandbits(4)
            key_ext.append(newkey)
        keys.append(bytes(key_ext))

    key = bytes(x for key in keys for x in key)

    output = bytes(key[i] ^ ord(c) for i, c in enumerate(string))
    return output


key = random.randbytes(N)
print("Random garbage:")
real_garb = "".join(random.choices(string.ascii_lowercase, k=2 * N))
garb = block_encrypt(key, real_garb)
print(garb.hex())
print("The flag:")
key = scramble(key)
flag = block_encrypt(key, FLAG)
print(flag.hex())
print("They look equally random, right? Pretty impressive!")
