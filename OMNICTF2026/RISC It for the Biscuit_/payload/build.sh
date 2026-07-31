#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python3 build_payload.py final_exploit -o exploit.bin
cp exploit.bin payload/exploit.bin
python3 build_payload.py local_exploit -o local_exploit.bin >/dev/null
cp local_exploit.bin payload/local_exploit.bin
