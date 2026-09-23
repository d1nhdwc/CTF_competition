FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/sh ctf

COPY chall /home/ctf/chall
RUN chown root:root /home/ctf/chall \
    && chmod 555 /home/ctf/chall

COPY entrypoint.sh /entrypoint.sh
RUN chmod 555 /entrypoint.sh

USER root
EXPOSE 6301
ENTRYPOINT ["/entrypoint.sh"]
