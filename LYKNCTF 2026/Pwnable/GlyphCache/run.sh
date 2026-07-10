#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export LD_LIBRARY_PATH="$DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if [ -x "$DIR/ld-linux-x86-64.so.2" ]; then
    exec "$DIR/ld-linux-x86-64.so.2" --library-path "$DIR" "$DIR/chall"
fi
exec "$DIR/chall"
