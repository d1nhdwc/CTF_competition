# Thanks Gemini. I suck at doing this kind of stuff
FROM ubuntu:22.04

# 1. Install dependencies
RUN apt-get update && apt-get install -y \
    socat \
    gcc \
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

# 2. Create a non-root user (Security is important!)
RUN useradd -m ctf

# 3. Set the working directory
WORKDIR /home/ctf

# 4. Copy files
COPY proper.c .
COPY flag.txt .

# 5. Compile the challenge
# Note: We disable protections like Stack Canaries and NX for a """Tutorial""" challenge
RUN gcc proper.c -o proper -fno-stack-protector -z execstack -no-pie

# 6. Set permissions
# We want the user to be able to execute the binary, but only read the flag
RUN chown root:ctf /home/ctf/flag.txt
RUN chmod 440 /home/ctf/flag.txt
RUN chown root:ctf /home/ctf/proper
RUN chmod 755 /home/ctf/proper

# 7. Expose the port socat will listen on
EXPOSE 1338

# 8. Run the service using socat
# This listens on port 1338 and spawns the 'proper' binary for every connection
USER ctf
CMD ["socat", "TCP-LISTEN:1338,reuseaddr,fork", "EXEC:./proper"]

# 9. Command line instructions
# docker build -t pwntorial .
# docker run -d -p 1338:1338 pwntorial

# Hopefully it works on CTFd!