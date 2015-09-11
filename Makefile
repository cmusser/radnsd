CC=gcc
CFLAGS=-g
all: rdnssd

rndssd: rndssd.c
	${CC} ${CFLAGS} -o $@ $<

clean:
	rm -f rdnssd
