FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y socat gdb file && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m pwnshadow

COPY bin/* /home/pwnshadow/

RUN chown -R root:pwnshadow /home/pwnshadow
RUN chmod -R 750 /home/pwnshadow

WORKDIR /home/pwnshadow
USER pwnshadow

EXPOSE 13332
CMD ["sh", "./init.sh"]