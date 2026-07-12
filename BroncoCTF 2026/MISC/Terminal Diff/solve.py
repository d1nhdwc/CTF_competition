from pathlib import Path

s = Path("flag.txt").read_text().strip()
w = 97

for i in range(0, len(s), w):
    print(s[i:i+w].replace("_", " "))
