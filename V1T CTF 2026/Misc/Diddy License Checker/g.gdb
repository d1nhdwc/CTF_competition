set pagination off
break http_get
run
printf "URL=%s\n", (char*)$rdi
finish
printf "RESP=%s\n", (char*)$rax
kill
quit
