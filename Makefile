CC=gcc
CFLAGS=-Wall

all: radnsd

radnsd: radnsd.c
	${CC} ${CFLAGS} -o $@ $<

install: radnsd
	/usr/bin/install -C -o root -g wheel radnsd ${DESTDIR}/${PREFIX}/sbin/
	/usr/bin/install -C -o root -g wheel radnsd.rc ${DESTDIR}/${PREFIX}/etc/rc.d/radnsd
	/usr/bin/install -C -o root -g wheel radnsd.8 ${DESTDIR}/${PREFIX}/man/man8/radnsd.8

clean:
	rm -f radnsd
