FROM ubuntu:24.04

# Install socat to serve the binary over the network
RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user named 'ctf' for security
RUN useradd -m ctf

# Copy flag to root directory with read permissions for the ctf group
COPY --chown=root:ctf --chmod=440 flag.txt /flag.txt

# Set the working directory
WORKDIR /home/ctf

# Copy the pre-compiled binary
COPY --chown=root:ctf --chmod=750 challenge .

# Switch to the unprivileged user
USER ctf

# Expose the port that socat will listen on
EXPOSE 1337

# Serve the binary over TCP using socat
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./challenge,stderr"]