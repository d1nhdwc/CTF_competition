FROM ubuntu:24.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    libc6 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m oura

COPY chall /home/oura/chall
COPY entrypoint.sh /entrypoint.sh

RUN chown -R root:oura /home/oura
RUN chmod 750 /home/oura /home/oura/chall
RUN chmod 755 /entrypoint.sh

WORKDIR /home/oura

EXPOSE 6304
ENTRYPOINT ["/entrypoint.sh"]
