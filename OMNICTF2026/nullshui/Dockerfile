FROM ubuntu:24.04@sha256:023f8a753c22258c9fe2d0005a7d28258038da7d620e9f93e9ad78aa266f9f11

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/ctf --shell /bin/bash ctf

COPY main /home/ctf/chall
COPY flag.txt /home/ctf/flag.txt

RUN chown -R root:root /home/ctf \
    && chmod 555 /home/ctf \
    && chmod 555 /home/ctf/chall \
    && chmod 444 /home/ctf/flag.txt

USER ctf
WORKDIR /home/ctf

EXPOSE 1337

ENTRYPOINT ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/chall,stderr"]
