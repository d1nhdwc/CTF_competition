FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        socat \
        ca-certificates \
        wget && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/libc-bin_2.35-0ubuntu3.11_amd64.deb && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.35-0ubuntu3.11_amd64.deb && \
    dpkg -i libc-bin_2.35-0ubuntu3.11_amd64.deb libc6_2.35-0ubuntu3.11_amd64.deb && \
    apt-mark hold libc6 libc-bin && \
    rm *.deb && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash pwnshadow

COPY bin/* /home/pwnshadow/

RUN chown -R root:pwnshadow /home/pwnshadow && \
    chmod -R 750 /home/pwnshadow

WORKDIR /home/pwnshadow
USER pwnshadow

EXPOSE 13334
CMD ["sh", "./init.sh"]
