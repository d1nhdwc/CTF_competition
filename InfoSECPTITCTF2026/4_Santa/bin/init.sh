#!/bin/sh
cd /home/pwn4
socat TCP-LISTEN:13334,reuseaddr,fork EXEC:./workshop,stderr