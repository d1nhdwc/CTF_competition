set -u
cd '/mnt/d/Documents/CTF_competition/DiceCTF 2026/RE'
for n in 20 40 60 80 100 120 140 160 180 200 300 400 500 600 700 800 900 1000 1200 1400 1600 1685; do
  head -n "$n" flag_riddle.txt > tmp_prefix.txt
  /usr/bin/timeout 1s ./interpreter tmp_prefix.txt > outp.bin 2>&1
  rc=$?
  sz=$(wc -c < outp.bin)
  pref=$(xxd -p -l 16 outp.bin)
  printf '%s rc=%s sz=%s pref=%s\n' "$n" "$rc" "$sz" "$pref"
done
