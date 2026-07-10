from zuc import ZUC
import zlib

KEY = bytes.fromhex("idontgivemykeyawaythiseasyhahaLOL")
IV = bytes.fromhex("blableblouthinkthisisrealiv?lmao")
flag = b"V1T{quackquackquackquacknotthateasy}"
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
def keystream_words(n_bytes: int):
    z = ZUC(KEY, IV)
    return [z._work_step() for _ in range((n_bytes + 3) // 4)]
def words_to_bytes(words, n_bytes: int):
    return b"".join(w.to_bytes(4, "big") for w in words)[:n_bytes]
words = keystream_words(len(flag))
keystream = words_to_bytes(words, len(flag))
cipher_flag = xor(flag, keystream)

leak1 = [((words[i] ^ words[i+1]) * 0x9e3779b1 >> 24) & 0xFF for i in range(len(words)-1)]
leak2 = [((words[i] * 0x45d9f3b) ^ (words[i] >> 16)) & 0xFFFF for i in range(len(words))]
leak3 = [bin(words[i]).count("1") for i in range(len(words))]
partial_crc = zlib.crc32(flag[:16])

print("cipher_flag:", cipher_flag.hex())
print("leak1:", leak1)
print("leak2:", leak2)
print("leak3:", leak3)
print("partial_crc:", hex(partial_crc))
# cipher_flag: 72901442adade9c53b7cb386eeb8b6765d42dbc58ec6d442e77057b7d5d2724afc2f4e232df02f9ff050
# leak1: [123, 38, 92, 78, 207, 178, 116, 75, 141, 163]
# leak2: [4226, 36575, 42265, 42988, 32134, 53660, 36202, 48971, 61905, 20150, 45745]
# leak3: [10, 18, 13, 17, 17, 19, 14, 13, 18, 16, 15]
# partial_crc: 0x32c29a97