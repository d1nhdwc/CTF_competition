#!/bin/sh
cd /home/pwn1
socat TCP-LISTEN:13339,reuseaddr,fork EXEC:./btvn,stderr