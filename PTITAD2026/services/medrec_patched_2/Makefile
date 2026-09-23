CC      ?= gcc
CFLAGS  ?= -std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
           -fno-omit-frame-pointer -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
LDFLAGS ?= -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

SRC = src/main.c src/front.c src/rend.c src/db.c src/util.c
OBJ = $(SRC:.c=.o)

all: medrecd

medrecd: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c src/common.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) medrecd

.PHONY: all clean
