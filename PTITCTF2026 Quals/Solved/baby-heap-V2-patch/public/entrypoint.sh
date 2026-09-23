#!/bin/sh
set -eu

if [ "${GZCTF_FLAG+x}" = "x" ]; then
    FLAG_VALUE="$GZCTF_FLAG"
elif [ "${FLAG+x}" = "x" ]; then
    FLAG_VALUE="$FLAG"
else
    FLAG_VALUE="PTITCTF{local_test_flag}"
fi

FLAG="$FLAG_VALUE"
echo "$FLAG" > /flag.txt
chmod 444 /flag.txt

cd /home/ctf
exec socat TCP-LISTEN:6300,reuseaddr,fork EXEC:/home/ctf/chall,stderr
