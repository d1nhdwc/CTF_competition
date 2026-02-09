#!/bin/sh
cd /home/pwn1
socat TCP-LISTEN:13333,reuseaddr,fork EXEC:./cybershop,stderr