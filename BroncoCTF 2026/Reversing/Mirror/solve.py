import hashlib

src = open("chall.py").read()
pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH")
specular_map = hashlib.sha256(src[pivot:pivot+300].encode()).digest()

blob = [17, 241, 10, 247, 215, 233, 146, 221, 156, 40, 37, 198, 153, 173, 10, 103, 20, 56, 232, 116, 208, 121, 53, 12, 122, 86, 127, 164, 109, 62, 88, 200, 127, 234, 5]
key = "MirrorMirror"

flag = ""
for i, b in enumerate(blob):
    reflection_byte = specular_map[i % len(specular_map)] ^ ord(key[i % len(key)])
    flag += chr(b ^ reflection_byte)

print(flag)
