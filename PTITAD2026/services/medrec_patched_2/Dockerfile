FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Hai uid rieng biet — day la lop cach ly chinh cua dich vu.
# KHONG duoc gop hai user nay lam mot.
RUN groupadd -g 1001 medrec-front \
 && useradd  -u 1001 -g 1001 -M -s /usr/sbin/nologin medrec-front \
 && groupadd -g 1002 medrec-rend \
 && useradd  -u 1002 -g 1002 -M -s /usr/sbin/nologin medrec-rend

WORKDIR /srv/medrec
COPY Makefile ./
COPY src ./src
RUN make

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9999
ENTRYPOINT ["/entrypoint.sh"]
