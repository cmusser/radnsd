CC=gcc

all: radnsd

radnsd: radnsd.c
	${CC} ${CFLAGS} -o $@ $<

install: radnsd
	/usr/bin/install -C -o root -g wheel radnsd ${DESTDIR}/${PREFIX}/bin/

clean:
	rm -f radnsd
