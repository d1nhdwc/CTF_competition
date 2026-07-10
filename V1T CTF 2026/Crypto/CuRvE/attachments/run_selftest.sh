#!/bin/bash
cd ~/curve
python3 -c 'import Crypto; print("pycryptodome ok")' 2>&1 | head -1
timeout 400 python3 selftest.py
