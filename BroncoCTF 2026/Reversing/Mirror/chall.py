import sys
import hashlib

def verify(attempt):
    try:
        with open(__file__, 'r') as f:
            src = f.read()
            pivot = src.index("MIRROR_SURFACE_DO_NOT_SCRATCH") 
            specular_map = hashlib.sha256(src[pivot:pivot+300].encode()).digest()
    except (FileNotFoundError, ValueError):
        return "The mirror has been shattered."

    if sys.gettrace() is not None:
        return "Nice try, but the glass turns opaque. No observers allowed!"
    if sys._getframe().f_code.co_name != 'verify' or __name__ != "__main__":
        return "You are looking at the mirror from a distorted angle."

    blob = [17, 241, 10, 247, 215, 233, 146, 221, 156, 40, 37, 198, 153, 173, 10, 103, 20, 56, 232, 116, 208, 121, 53, 12, 122, 86, 127, 164, 109, 62, 88, 200, 127, 234, 5]
    try:
        looking_glass = "MirrorMirror"
        flag = ""
        for i, b in enumerate(blob):
            reflection_byte = specular_map[i % len(specular_map)] ^ ord(looking_glass[i % len(looking_glass)])
            flag += chr(b ^ reflection_byte)
            
        if attempt == flag:
            return f"The reflection clears!"
    except Exception:
        pass

    return "All you see is a distorted blur. (Wrong Password)"

if __name__ == "__main__":
    inp = input("Enter the password to gaze into the mirror: ")
    print(verify(inp))