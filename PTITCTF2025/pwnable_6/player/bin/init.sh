#!/bin/sh
cd /home/pwnshadow
socat TCP-LISTEN:13330,reuseaddr,fork EXEC:./pwn6,stderr