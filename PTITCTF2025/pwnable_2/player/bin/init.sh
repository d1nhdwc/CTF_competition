#!/bin/sh
cd /home/pwnshadow
socat TCP-LISTEN:13333,reuseaddr,fork EXEC:./pwn2,stderr