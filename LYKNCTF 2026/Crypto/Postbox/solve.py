#!/usr/bin/env python3
import sys
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

URL = "http://CHANGE_ME:8080"
BLOCK = 16

# Nếu server chịu được thì để 32. Nếu fail/timeouts thì giảm 16 hoặc 8.
PARALLEL = 32
TIMEOUT = 4
RETRIES = 2

# Ta đã biết 3 block đầu:
KNOWN_PREFIX = b"session: user=guest; role=viewer; flag=LYKNCTF{f"

def is_valid_padding_response(r):
    try:
        obj = r.json()
        return obj.get("ok") is True
    except Exception:
        low = r.text.lower()
        return "ok" in low and "bad padding" not in low and "error" not in low

def oracle(iv, block):
    payload = {
        "iv": iv.hex(),
        "ciphertext": block.hex(),
    }

    for _ in range(RETRIES):
        try:
            r = requests.post(URL + "/decrypt", json=payload, timeout=TIMEOUT)
            return is_valid_padding_response(r)
        except Exception:
            time.sleep(0.03)

    return False

def get_token():
    r = requests.get(URL + "/login", timeout=TIMEOUT)
    r.raise_for_status()
    obj = r.json()

    iv = bytes.fromhex(obj["iv"])
    ct = bytes.fromhex(obj["ciphertext"])

    print("[+] iv =", iv.hex())
    print("[+] ciphertext =", ct.hex())
    print("[+] blocks =", len(ct) // BLOCK)

    return iv, ct

def unique_bytes(data):
    out = []
    seen = set()
    for x in data:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

# Ưu tiên ký tự hay xuất hiện trong flag trước.
PLAIN_PRIORITY = unique_bytes(
    b"abcdefghijklmnopqrstuvwxyz"
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    b"0123456789"
    b"{}_-=!@#$%^&*.:;,"
    b" "
    + bytes(range(1, 17))
    + bytes(range(32, 127))
    + bytes(range(256))
)

def build_guess_order(original_prev_byte, pad):
    guesses = []
    seen = set()

    for p in PLAIN_PRIORITY:
        # plaintext = intermediate XOR original_prev
        # intermediate = plaintext XOR original_prev
        # crafted = intermediate XOR pad
        g = p ^ original_prev_byte ^ pad
        if g not in seen:
            seen.add(g)
            guesses.append(g)

    return guesses

def test_guess(base_crafted, idx, guess, target):
    crafted = bytearray(base_crafted)
    crafted[idx] = guess
    ok = oracle(bytes(crafted), target)
    return guess, ok

def confirm_guess(base_crafted, idx, guess, pad, target):
    crafted = bytearray(base_crafted)
    crafted[idx] = guess

    if not oracle(bytes(crafted), target):
        return False

    # Flip byte ngoài vùng padding: padding vẫn phải valid.
    if idx > 0:
        t = bytearray(crafted)
        t[idx - 1] ^= 1
        if not oracle(bytes(t), target):
            return False

    # Flip byte trong vùng padding đã recover: padding phải invalid.
    if pad > 1:
        t = bytearray(crafted)
        t[-1] ^= 1
        if oracle(bytes(t), target):
            return False

    return True

def recover_block(target_block, original_prev_block, block_index):
    intermediate = bytearray(BLOCK)
    crafted = bytearray(b"\x00" * BLOCK)
    plaintext = bytearray(b"." * BLOCK)

    print(f"\n[*] Recovering block {block_index}")

    for pad in range(1, BLOCK + 1):
        idx = BLOCK - pad

        for j in range(BLOCK - 1, idx, -1):
            crafted[j] = intermediate[j] ^ pad

        found = None
        guesses = build_guess_order(original_prev_block[idx], pad)

        for start in range(0, len(guesses), PARALLEL):
            batch = guesses[start:start + PARALLEL]

            with ThreadPoolExecutor(max_workers=min(PARALLEL, len(batch))) as ex:
                futs = [
                    ex.submit(test_guess, bytes(crafted), idx, g, target_block)
                    for g in batch
                ]

                valid_guesses = []

                for fut in as_completed(futs):
                    try:
                        g, ok = fut.result()
                    except Exception:
                        continue

                    if ok:
                        valid_guesses.append(g)

            for g in valid_guesses:
                if confirm_guess(bytes(crafted), idx, g, pad, target_block):
                    found = g
                    break

            if found is not None:
                break

        if found is None:
            print(f"[!] Failed at block={block_index}, pad={pad}, idx={idx}")
            print("[!] Nếu instance chưa hết hạn, thử giảm PARALLEL xuống 16 hoặc 8.")
            sys.exit(1)

        intermediate[idx] = found ^ pad
        plaintext[idx] = intermediate[idx] ^ original_prev_block[idx]

        preview = bytes(c if 32 <= c <= 126 else ord(".") for c in plaintext)

        print(
            f"    pad={pad:02d} idx={idx:02d} "
            f"byte={plaintext[idx]:02x} "
            f"block_so_far={preview!r}"
        )

    print(f"[+] plaintext block {block_index}: {bytes(plaintext)!r}")
    return bytes(plaintext)

def main():
    global URL

    if len(sys.argv) >= 2:
        URL = sys.argv[1].rstrip("/")

    print("[*] URL =", URL)
    print("[*] PARALLEL =", PARALLEL)

    iv, ct = get_token()
    ct_blocks = [ct[i:i + BLOCK] for i in range(0, len(ct), BLOCK)]

    if len(ct_blocks) != 6:
        print("[!] Unexpected block count:", len(ct_blocks))

    recovered = bytearray(KNOWN_PREFIX)

    # Bạn đã có block 0,1,2. Giờ chỉ decrypt 3,4,5.
    for i in range(2, len(ct_blocks)):
        prev = iv if i == 0 else ct_blocks[i - 1]
        plain = recover_block(ct_blocks[i], prev, i)
        recovered += plain

        print("\n[+] recovered so far:")
        print(bytes(recovered))

        m = re.search(rb"LYKNCTF\{[^}]+\}", bytes(recovered))
        if m:
            print("\n[+] FLAG:", m.group(0).decode(errors="replace"))
            return

    print("\n========== FINAL RECOVERED ==========")
    print(bytes(recovered))

    m = re.search(rb"LYKNCTF\{[^}]+\}", bytes(recovered))
    if m:
        print("\n[+] FLAG:", m.group(0).decode(errors="replace"))
    else:
        print("\n[!] Chưa thấy dấu `}`. Paste output cuối cho mình xem tiếp.")

if __name__ == "__main__":
    main()