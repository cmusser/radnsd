CFLAGS=-Wall
PREFIX?=/usr/local

all: radnsd

radnsd: radnsd.c
	${CC} ${CFLAGS} -o $@ $<

install: radnsd
	cp radnsd ${DESTDIR}/${PREFIX}/sbin/
	cp radnsd.8 ${DESTDIR}/${PREFIX}/man/man8/radnsd.8

clean:
	rm -f radnsd
