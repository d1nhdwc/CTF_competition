#!/usr/bin/env bash
set -Eeuo pipefail

readonly APP_HOME=/home/chrome
readonly FLAG_FILE="${APP_HOME}/flag.txt"

cd "${APP_HOME}"

FLAG_VALUE="${GZCTF_FLAG:-${FLAG:-PTITCTF{fake_flag}}}"

# The same container may be restarted; make the previous runtime flag writable
# before replacing it, then lock it back to read-only mode.
if [[ -e "${FLAG_FILE}" ]]; then
    chmod 0600 "${FLAG_FILE}"
fi
printf "%s\n" "$FLAG_VALUE" > "${FLAG_FILE}"
chmod 0440 "${FLAG_FILE}"

unset GZCTF_FLAG
unset FLAG

exec /usr/bin/socat TCP-LISTEN:6303,reuseaddr,fork \
    EXEC:/home/chrome/chall,stderr
