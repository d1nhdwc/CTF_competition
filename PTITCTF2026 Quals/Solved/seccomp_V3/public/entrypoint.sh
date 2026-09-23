#!/bin/sh
set -eu

if [ -n "${GZCTF_FLAG:-}" ]; then
    FLAG_VALUE="$GZCTF_FLAG"
elif [ -n "${FLAG:-}" ]; then
    FLAG_VALUE="$FLAG"
else
    FLAG_VALUE='PTITCTF{local_test_flag}'
fi

echo "$FLAG_VALUE" > /flag.txt
chmod 444 /flag.txt

cd /home/ctf
exec socat TCP-LISTEN:6302,reuseaddr,fork EXEC:/home/ctf/chall,stderr
