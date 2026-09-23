#!/bin/bash
set -e

cd /home/oura

FLAG_VALUE="${GZCTF_FLAG:-${FLAG:-PTITCTF{fake_flag}}"

printf '%s\n' "$FLAG_VALUE" > /home/oura/flag.txt
chown root:oura /home/oura/flag.txt
chmod 440 /home/oura/flag.txt

unset GZCTF_FLAG FLAG FLAG_VALUE

exec socat TCP-LISTEN:6304,reuseaddr,fork EXEC:/home/oura/chall,stderr
