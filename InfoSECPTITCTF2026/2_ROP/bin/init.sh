#!/bin/sh
cd /home/pwn2
socat TCP-LISTEN:13332,reuseaddr,fork EXEC:./vuln,stderr