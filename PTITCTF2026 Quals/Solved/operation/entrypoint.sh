#!/bin/bash
set -e

export FLAG="${GZCTF_FLAG:-${FLAG:-PTITCTF{fake_flag}}}"

printf "%s\n" "$FLAG" > /home/ctf/flag.txt
chown root:ctf /home/ctf/flag.txt
chmod 440 /home/ctf/flag.txt

unset GZCTF_FLAG
unset FLAG

cd /home/ctf
exec su -s /bin/sh ctf -c 'exec socat TCP-LISTEN:6305,reuseaddr,fork EXEC:/home/ctf/chall,stderr'
