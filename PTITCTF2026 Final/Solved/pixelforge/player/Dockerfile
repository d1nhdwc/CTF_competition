# Ubuntu 25.04 (Plucky), linux/amd64, glibc 2.41.
FROM ubuntu:25.04@sha256:34e8533bf27ac50f60bec267f6ce18c9aeb9556574e1ec1a8ce89926d32ea8f3

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash chrome

RUN install -d -o chrome -g chrome -m 0750 /var/lib/chrome \
    && ln -s /var/lib/chrome/flag.txt /home/chrome/flag.txt

COPY --chown=root:chrome chall /home/chrome/chall
COPY entrypoint.sh /usr/local/bin/chrome-entrypoint

RUN chown root:chrome /home/chrome \
    && chmod 0750 /home/chrome \
    && chmod 0750 /home/chrome/chall \
    && chmod 0755 /usr/local/bin/chrome-entrypoint

WORKDIR /home/chrome
USER chrome

EXPOSE 6303
ENTRYPOINT ["/usr/local/bin/chrome-entrypoint"]
