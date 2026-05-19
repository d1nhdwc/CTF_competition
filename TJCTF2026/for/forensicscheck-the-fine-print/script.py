from pathlib import Path

bits = []
for i in range(1, 249):
    data = Path(f"{i:03d}.png").read_bytes()

    bits.append(data[26] & 1)

out = bytearray()
for i in range(0, len(bits), 8):
    byte = 0
    for bit in bits[i:i+8]:
        byte = (byte << 1) | bit
    out.append(byte)

print(out.decode())