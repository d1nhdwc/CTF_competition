FROM ubuntu:24.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y socat

RUN dpkg --add-architecture i386 
RUN apt-get update && apt-get install -y libc6:i386 libstdc++6:i386 lib32gcc-s1 gdb

RUN useradd -m ctf

COPY chall /home/ctf/chall
COPY entrypoint.sh /entrypoint.sh

RUN chown -R root:ctf /home/ctf
RUN chmod -R 750 /home/ctf
RUN chmod 755 /entrypoint.sh

WORKDIR /home/ctf

EXPOSE 6305
ENTRYPOINT ["/entrypoint.sh"]
