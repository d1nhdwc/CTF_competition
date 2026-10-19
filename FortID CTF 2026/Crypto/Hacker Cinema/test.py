#!/usr/bin/env python3
import json
import hashlib
import subprocess
import tempfile
from urllib.parse import urljoin, urlparse, parse_qs

import requests

BASE = "https://hacker-cinema-296dee9a43fd.inst5.ctf.fortid.com"
SEAT = "C06"

# Chỉnh vùng này quanh boundary Feb 28/29 year -0001 mà bạn tìm được.
# Có thể scan rộng trước theo giờ, sau đó thu hẹp theo phút/giây.
START = -62193916800
END   = -62193571200
STEP  = 3600

sess = requests.Session()

def canonical_json(obj):
    # Match đủ tốt với PHP canonical_json cho object ticket đơn giản:
    # ksort recursive + json_encode không escape slash/unicode.
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )

def buy_and_decode(ts):
    r = sess.post(
        urljoin(BASE, "/buy"),
        data={
            "seat": SEAT,
            "screening": str(ts),
        },
        allow_redirects=False,
    )

    if r.status_code != 303:
        print(f"[!] buy failed ts={ts} status={r.status_code}")
        return None

    loc = r.headers.get("Location", "")
    tid = parse_qs(urlparse(loc).query).get("id", [None])[0]
    if not tid:
        print(f"[!] no ticket id ts={ts} loc={loc}")
        return None

    img = sess.get(urljoin(BASE, "/ticket.png"), params={"id": tid})
    if img.status_code != 200:
        print(f"[!] ticket.png failed ts={ts} id={tid} status={img.status_code}")
        return None

    with tempfile.NamedTemporaryFile(suffix=".png") as f:
        f.write(img.content)
        f.flush()

        raw = subprocess.check_output(
            ["zbarimg", "--raw", "-q", f.name],
            text=True,
        ).strip()

    env = json.loads(raw)
    ticket = env["ticket"]
    sig = env["signature"]

    msg = canonical_json(ticket).encode()
    z = hashlib.sha256(msg).hexdigest()

    return {
        "ts": ts,
        "id": tid,
        "ticket": ticket,
        "msg": msg.decode(),
        "z": z,
        "r": sig["r"],
        "s": sig["s"],
        "env": env,
    }

groups = {}

for ts in range(START, END + 1, STEP):
    item = buy_and_decode(ts)
    if item is None:
        continue

    r = item["r"]
    groups.setdefault(r, []).append(item)

    print(
        f"ts={ts} "
        f"date={item['ticket']['date']} "
        f"winner={item['ticket']['winner']} "
        f"r={item['r'][:16]}... "
        f"s={item['s'][:16]}..."
    )

print("\n[+] Searching same-r / different-message pairs...\n")

found = False

for r, items in groups.items():
    if len(items) < 2:
        continue

    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a = items[i]
            b = items[j]

            same_r = a["r"] == b["r"]
            diff_z = a["z"] != b["z"]
            diff_s = a["s"] != b["s"]
            diff_ticket = a["ticket"] != b["ticket"]

            if same_r and diff_z and diff_s:
                found = True
                print("[!!!] EXPLOITABLE PAIR FOUND")
                print(f"r = {r}")
                print()

                print("[A]")
                print(f"ts = {a['ts']}")
                print(f"z  = {a['z']}")
                print(f"s  = {a['s']}")
                print(json.dumps(a["ticket"], indent=2))

                print("\n[B]")
                print(f"ts = {b['ts']}")
                print(f"z  = {b['z']}")
                print(f"s  = {b['s']}")
                print(json.dumps(b["ticket"], indent=2))

                print("\nMessages:")
                print(a["msg"])
                print(b["msg"])
                raise SystemExit

if not found:
    print("[-] No exploitable same-r/different-message pair in this range.")