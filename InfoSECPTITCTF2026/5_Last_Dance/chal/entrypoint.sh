#!/usr/bin/env bash
set -euo pipefail

PORT="${EXPOSED_PORT:-13335}"
TIMEOUT="${TIMEOUT:-60}"

if [[ -f /app/libc.so.6 ]]; then
  PRELOAD_ENV='LD_PRELOAD=/app/libc.so.6'
else
  PRELOAD_ENV=''
fi

socat TCP-LISTEN:${PORT},reuseaddr,fork \
  EXEC:"timeout -s SIGKILL ${TIMEOUT} env ${PRELOAD_ENV} /app/chall"