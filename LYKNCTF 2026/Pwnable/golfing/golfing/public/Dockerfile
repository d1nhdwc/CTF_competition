FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    cpio \
    gzip \
    ncat \
    qemu-system-misc \
 && rm -rf /var/lib/apt/lists/*

COPY Image initramfs.cpio.gz flag.txt run.sh /app/

RUN chmod 0555 /app/run.sh \
 && mkdir -p /tmp/initramfs \
 && cd /tmp/initramfs \
 && gzip -dc /app/initramfs.cpio.gz | cpio -id --quiet \
 && install -m 0444 /app/flag.txt flag.txt \
 && find . -print0 | sort -z | cpio --null --quiet -o -H newc | gzip -9 > /app/initramfs.cpio.gz \
 && rm -rf /tmp/initramfs /app/flag.txt

EXPOSE 9002

CMD [ "/app/run.sh" ]
