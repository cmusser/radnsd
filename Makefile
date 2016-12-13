CFLAGS=-Wall
PREFIX?=/usr/local

all: radnsd

radnsd: radnsd.c
	${CC} ${CFLAGS} -o $@ $<

install: radnsd
	cp radnsd ${PREFIX}/sbin/
	cp radnsd.8 ${PREFIX}/man/man8/radnsd.8

clean:
	rm -f radnsd
