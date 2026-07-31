import subprocess
from base64 import b64decode
import pathlib


script_dir = pathlib.Path(__file__).parent.resolve()
bin_path = script_dir / "RV64VMv4.exe"
pattern_path = script_dir / ".flag_pattern"
exploit_path = script_dir / "exploit.bin"

try:
    with open(pattern_path, "rb") as pattern_file:
        MAGIC_PATTERN = pattern_file.read().strip()
except FileNotFoundError:
    print("[-] .flag_pattern file not found")
    exit(1)

enc_data = input("Enter payload encoded in Base64: ")

with open(exploit_path, "wb") as f:
    data = b64decode(enc_data)
    print("[*] Decoding and writing to exploit.bin...")
    print(f"[*] Raw payload size: {len(data)}")
    f.write(data)

try:
    result = subprocess.run(
        [bin_path, exploit_path],
        capture_output=True,
        check=False
    )
    output = result.stdout + result.stderr
except FileNotFoundError:
    print(f"[-] {bin_path.name} not found")
    exit(1)

flag_found = False
for line in output.split(b"\n"):
    if MAGIC_PATTERN in line:
        print(line.decode("utf-8", errors="ignore").strip())
        flag_found = True
        break

if not flag_found:
    print("[-] No flag")
