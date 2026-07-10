#!/bin/bash
cd "/mnt/d/Documents/CTF_competition/V1T CTF 2026/Misc/Diddy License Checker"
cp diddy /tmp/diddy && chmod +x /tmp/diddy
cp g.gdb /tmp/g.gdb
sed -i 's/\r$//' /tmp/g.gdb
printf 'duck\n01123584371808876415628101123584\nlicense-for-test\n' > /tmp/in.txt
gdb -q -batch -x /tmp/g.gdb /tmp/diddy < /tmp/in.txt 2>&1
