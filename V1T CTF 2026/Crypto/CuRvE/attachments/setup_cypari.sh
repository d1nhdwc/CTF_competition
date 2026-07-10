#!/bin/bash
pip3 install --break-system-packages cypari2 > /tmp/pip.log 2>&1
tail -3 /tmp/pip.log
python3 - <<'PY'
import cypari2
pari = cypari2.Pari()
E = pari.ellinit([pari.Mod(2,101), pari.Mod(3,101)])
print("cypari2 ellcard", pari.ellcard(E))
PY
