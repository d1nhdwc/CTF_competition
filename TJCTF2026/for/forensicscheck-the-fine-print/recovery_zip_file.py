from pathlib import Path

b = Path("logo.png").read_bytes()

Path("carved.zip").write_bytes(b[14276:])