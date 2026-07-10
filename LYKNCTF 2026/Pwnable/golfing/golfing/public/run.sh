#!/bin/sh
set -eu

ncat -lnvp 9002 -k -c 'timeout 60s ncat localhost 1337' &
exec qemu-system-riscv64 \
    -m 128M \
    -machine virt \
    -kernel Image \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=-1 rdinit=/init net.ifnames=0" \
    -netdev user,id=net0,hostfwd=tcp:0.0.0.0:1337-:4444 \
    -device virtio-net-device,netdev=net0 \
    -smp 1 \
    -monitor /dev/null \
    -no-reboot \
    -nographic
