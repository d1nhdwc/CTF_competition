#!/bin/sh
cd /home/pwnshadow
socat TCP-LISTEN:13339,reuseaddr,fork EXEC:./pwn5,stderr