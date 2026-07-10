#!/bin/sh
set -eu

# Requires qemu-system-riscv64 locally.
# Port 9002 on host forwards to chall's nc listener on guest port 4444.
qemu-system-riscv64 \
  -machine virt \
  -m 256M \
  -nographic \
  -kernel ./Image \
  -initrd ./initramfs.cpio.gz \
  -append "console=ttyS0 rdinit=/init" \
  -netdev user,id=net0,hostfwd=tcp::9002-:4444 \
  -device virtio-net-device,netdev=net0
