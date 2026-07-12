enc = bytes.fromhex("24509693cf564e7aa761d40e2415a3e389be4c00")

def u32(x):
    return x & 0xffffffff

def rol32(x, n):
    n &= 31
    return u32((x << n) | (x >> (32 - n))) if n else u32(x)

talk_bonus = 21

seed = u32(talk_bonus * 0x11)
seed = u32(seed ^ 0xc47b4cd0)
seed = u32(seed ^ (seed >> 16))
seed = u32(seed * 0x7feb352d)
seed = u32(seed ^ (seed >> 15))
seed = u32(seed * 0x846ca68b)
seed = u32(seed ^ (seed >> 16))

state = 0x5a
out = []

for i in range(1, len(enc)):
    x = u32(i * 0x9e3779b9)
    x ^= seed
    x = rol32(x, (i - 1) % 13)
    x ^= state

    out.append(enc[i - 1] ^ (x & 0xff))
    state = u32(state + 0x33)

    if enc[i] == 0:
        break

print(bytes(out).decode())
