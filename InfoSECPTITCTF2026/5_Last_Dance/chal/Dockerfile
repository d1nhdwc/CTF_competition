FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      socat coreutils locales ca-certificates \
      curl binutils gcc make \
 && rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8

WORKDIR /app
COPY . /app

RUN test -f /app/entrypoint.sh && test -f /app/chall
RUN chmod 755 /app/entrypoint.sh /app/chall

EXPOSE 13335

ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
