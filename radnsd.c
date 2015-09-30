#include <sys/event.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* TODO: option processing and fork. Take RA lifetime into account */
struct dns_str {
	char		str       [256];
			TAILQ_ENTRY   (dns_str) entries;
};
TAILQ_HEAD(rdnss_list_t, dns_str) rdnss_list = TAILQ_HEAD_INITIALIZER(rdnss_list);
TAILQ_HEAD(dnssl_list_t, dns_str) dnssl_list = TAILQ_HEAD_INITIALIZER(dnssl_list);

struct kevent	change[4];
int		log_upto = LOG_NOTICE;
bool		fflag = false;
bool		dflag = false;
int		rssock;
struct msghdr	rcvmhdr;
u_char		answer  [1500];
struct iovec	rcviov[1];
static struct sockaddr_in6 from;
intptr_t	rdnss_ltime = 0;
intptr_t	dnssl_ltime = 0;

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))
#define ADDRCOUNT(rdnss_p) ((rdnss_p->nd_opt_rdnss_len - 1) / 2)

#define RDNSS_TIMER_ID 1
#define DNSSL_TIMER_ID 2

#define ALLROUTER "ff02::2"
static struct sockaddr_in6 sin6_allrouters = {
	sizeof(sin6_allrouters),
	AF_INET6,
	0,
	0,
	IN6ADDR_ANY_INIT,
	0
};

void		usage(void);
void		msg   (int priority, const char *func, const char *msg,...);
void		clear_rdnss_list(void);
void		clear_dnssl_list(void);
int		sockopen   (void);
int		process_rdnss_opt(struct nd_opt_rdnss *rdnss_p, int cur_idx);
int		process_dnssl_opt(struct nd_opt_dnssl *dnssl_p, int cur_idx);
int		sock_input (void);
void		write_resolv_conf(void);
void		rdnss_timer(intptr_t data);
void		dnssl_timer(intptr_t data);

void
usage(void)
{
	fprintf(stderr, "usage: radnsd [-fdh]\n");
	exit(EXIT_FAILURE);

}

void
msg(int priority, const char *func, const char *msg,...)
{
	va_list		ap;
	char		buf       [BUFSIZ];

	va_start(ap, msg);
	if (fflag) {
		if (priority <= log_upto) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, "\n");
		}
	} else {
		snprintf(buf, sizeof(buf), "<%s> %s", func, msg);
		msg = buf;
		vsyslog(priority, msg, ap);
	}
	va_end(ap);
}

void
clear_rdnss_list(void)
{
	struct dns_str *cur_str;

	while (!TAILQ_EMPTY(&rdnss_list)) {
		cur_str = TAILQ_FIRST(&rdnss_list);
		TAILQ_REMOVE(&rdnss_list, cur_str, entries);
		free(cur_str);
	}
}

void
clear_dnssl_list(void)
{
	struct dns_str *cur_str;

	while (!TAILQ_EMPTY(&dnssl_list)) {
		cur_str = TAILQ_FIRST(&dnssl_list);
		TAILQ_REMOVE(&dnssl_list, cur_str, entries);
		free(cur_str);
	}
}

int
sockopen(void)
{
	int		on;
	struct icmp6_filter filt;
	int		rcvcmsglen;
	static u_char  *rcvcmsgbuf = NULL;

	rcvcmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		CMSG_SPACE(sizeof(int));
	if (rcvcmsgbuf == NULL && (rcvcmsgbuf = malloc(rcvcmsglen)) == NULL) {
		msg(LOG_ERR, __func__,
			"malloc for receive msghdr failed");
		return (-1);
	}
	memset(&sin6_allrouters, 0, sizeof(struct sockaddr_in6));
	sin6_allrouters.sin6_family = AF_INET6;
	sin6_allrouters.sin6_len = sizeof(sin6_allrouters);
	if (inet_pton(AF_INET6, ALLROUTER,
		      &sin6_allrouters.sin6_addr.s6_addr) != 1) {
		msg(LOG_ERR, __func__, "inet_pton failed for %s",
			ALLROUTER);
		return (-1);
	}
	if ((rssock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		msg(LOG_ERR, __func__, "socket: %s", strerror(errno));
		return (-1);
	}
	/* Return receiving interface */
	on = 1;
	if (setsockopt(rssock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0) {
		msg(LOG_ERR, __func__, "IPV6_RECVPKTINFO: %s",
			strerror(errno));
		exit(1);
	}
	/* Accept only router advertisements on the socket */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	if (setsockopt(rssock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		       sizeof(filt)) == -1) {
		msg(LOG_ERR, __func__, "setsockopt(ICMP6_FILTER): %s",
			strerror(errno));
		return (-1);
	}
	/* initialize msghdr for receiving packets */
	rcviov[0].iov_base = (caddr_t) answer;
	rcviov[0].iov_len = sizeof(answer);
	rcvmhdr.msg_name = (caddr_t) & from;
	rcvmhdr.msg_namelen = sizeof(from);
	rcvmhdr.msg_iov = rcviov;
	rcvmhdr.msg_iovlen = 1;
	rcvmhdr.msg_control = (caddr_t) rcvcmsgbuf;
	rcvmhdr.msg_controllen = rcvcmsglen;

	return (rssock);
}

void
write_resolv_conf(void)
{
	FILE           *resolv_conf;
	struct dns_str *cur;
	char		dnssl     [256] = {'\0'};

	resolv_conf = fopen("/etc/resolv.conf", "w");
	if (resolv_conf != NULL) {
		strlcpy(dnssl, "search", sizeof(dnssl));
		TAILQ_FOREACH(cur, &dnssl_list, entries) {
			if (strlcat(dnssl, " ", sizeof(dnssl)) <= sizeof(dnssl))
				strlcat(dnssl, cur->str, sizeof(dnssl));
		}
		fprintf(resolv_conf, "%s\n", dnssl);

		TAILQ_FOREACH(cur, &rdnss_list, entries) {
			fprintf(resolv_conf, "nameserver %s\n", cur->str);
		}
		fclose(resolv_conf);
	}
}

int
process_rdnss_opt(struct nd_opt_rdnss *rdnss, int cur_idx)
{

	intptr_t	ltime;
	uint8_t		i;
	struct dns_str *rdnss_str;
	struct in6_addr *cur_addr_p;

	ltime = (intptr_t) ntohl(rdnss->nd_opt_rdnss_lifetime);
	msg(LOG_INFO, __func__, "RDNSS Option (lifetime: %d, will expire: %d, 8-octet units: %u)",
		ltime, time(NULL) + ltime, rdnss->nd_opt_rdnss_len);


	if (rdnss_ltime > 0)
		EV_SET(&change[cur_idx++], RDNSS_TIMER_ID, EVFILT_TIMER, EV_DELETE, 0, 0, 0);
	rdnss_ltime = ltime * 1000;

	if (rdnss_ltime > 0) {
		EV_SET(&change[cur_idx++], RDNSS_TIMER_ID, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
		       0, rdnss_ltime, 0);
	}
	for (cur_addr_p = (struct in6_addr *)(rdnss + 1), i = 0;
	     i < ADDRCOUNT(rdnss);
	     i++, cur_addr_p++) {
		rdnss_str = malloc(sizeof(struct dns_str));
		if (rdnss_str != NULL) {
			inet_ntop(AF_INET6, cur_addr_p, rdnss_str->str,
				  sizeof(rdnss_str->str));
			TAILQ_INSERT_TAIL(&rdnss_list, rdnss_str, entries);
		}
	}

	return cur_idx;
}

int
process_dnssl_opt(struct nd_opt_dnssl *dnssl, int cur_idx)
{
	intptr_t	ltime;
	uint8_t        *cur, prev = 0;
	bool		skip = false;
	char		label     [64];
	char		segment   [65];
	char		domain    [256] = {'\0'};
	struct dns_str *dnssl_str;


	ltime = (intptr_t) ntohl(dnssl->nd_opt_dnssl_lifetime);
	msg(LOG_INFO, __func__, "DNSSL Option (lifetime: %d, will expire: %d, 8-octet units: %u)",
		ltime, time(NULL) + ltime, dnssl->nd_opt_dnssl_len);

	if (dnssl_ltime > 0)
		EV_SET(&change[cur_idx++], DNSSL_TIMER_ID, EVFILT_TIMER, EV_DELETE, 0, 0, 0);
	dnssl_ltime = ltime * 1000;

	if (dnssl_ltime > 0) {
		EV_SET(&change[cur_idx++], DNSSL_TIMER_ID, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
		       0, dnssl_ltime, 0);
	}
	cur = (uint8_t *) (dnssl + 1);
	while (!(*cur == 0 && prev == 0)) {

		if (*cur == 0) {
			/* The end of a series of labels. */
			if (!skip) {
				dnssl_str = malloc(sizeof(struct dns_str));
				if (dnssl_str != NULL) {
					strlcpy(dnssl_str->str, domain, sizeof(dnssl_str->str));
					TAILQ_INSERT_TAIL(&dnssl_list, dnssl_str, entries);
				}
				bzero(domain, sizeof(domain));
			}
			skip = false;
		} else if (skip) {
			/*
			 * Don't process. This happens if an individual label
			 * or the whole domain was too long.
			 */
			continue;
		} else {
			if (*cur < sizeof(label)) {
				bzero(label, sizeof(label));
				memcpy(label, cur + 1, *cur);
				snprintf(segment, sizeof(segment), "%s%s",
					 prev == 0 ? "" : ".", label);
				if (strlcat(domain, segment, sizeof(domain)) <= sizeof(domain)) {
				} else {
					skip = true;
					msg(LOG_ERR, __func__, "domain \"%s\" too long, skipping", domain);
				}
			} else {
				skip = true;
				msg(LOG_ERR, __func__, "label \"%s\" too long, skipping domain", label);
			}
		}
		/*
		 * Advance to the next label, regardless of whether the
		 * current one was processed.
		 */
		prev = *cur;
		cur += (*cur + 1);
	}

	return cur_idx;
}

int
sock_input(void)
{
	int		i;
	struct nd_router_advert *ra;
	char           *cur, *end;
	struct nd_opt_hdr *opt;
	int		nchanges = 0;

	if ((i = recvmsg(rssock, &rcvmhdr, 0)) < 0) {
		msg(LOG_ERR, __func__, "recvmsg: %s", strerror(errno));
		return 0;
	}
	clear_rdnss_list();
	clear_dnssl_list();

	ra = rcviov[0].iov_base;
	msg(LOG_INFO, __func__, "RA received at %lu (lifetime: %lu)",
		time(NULL), ntohs(ra->nd_ra_router_lifetime));

	end = rcviov[0].iov_base + i;
	cur = (char *)(ra + 1);
	while (cur < end) {
		opt = (struct nd_opt_hdr *)cur;
		switch (opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
		case ND_OPT_PREFIX_INFORMATION:
		case ND_OPT_REDIRECTED_HEADER:
		case ND_OPT_MTU:
		case ND_OPT_ROUTE_INFO:
			//Recognized, but not relevant
			break;
		case ND_OPT_RDNSS:
			nchanges = process_rdnss_opt((struct nd_opt_rdnss *)opt, nchanges);
			break;
		case ND_OPT_DNSSL:
			nchanges = process_dnssl_opt((struct nd_opt_dnssl *)opt, nchanges);
			break;
		default:
			msg(LOG_WARNING, __func__, "unrecognized message: %d",
				opt->nd_opt_type);
		}
		cur += (opt->nd_opt_len * 8);
	}

	if (nchanges > 0)
		write_resolv_conf();

	return nchanges;
}

void
rdnss_timer(intptr_t data)
{
	msg(LOG_DEBUG, __func__, "RDNSS: expired: %u, count %d", time(NULL), data);
	rdnss_ltime = 0;
	clear_rdnss_list();
	write_resolv_conf();
}

void
dnssl_timer(intptr_t data)
{
	msg(LOG_DEBUG, __func__, "DNSSL: expired: %u, count %d", time(NULL), data);
	dnssl_ltime = 0;
	clear_dnssl_list();
	write_resolv_conf();
}

int 
main(int argc, char *argv[])
{
	struct kevent	event[3];
	int		ch, kq, s, nchanges, nev, i;
	const char	*opts;

	opts = "dfh";

	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 'f':
			dflag = 1;
			fflag = 1;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	/* set log level */
	if (dflag == 1)
		log_upto = LOG_INFO;
	if (!fflag) {
		char *ident;
		ident = strrchr(argv[0], '/');
		if (!ident)
			ident = argv[0];
		else
			ident++;
		openlog(ident, LOG_NDELAY|LOG_PID, LOG_DAEMON);
		if (log_upto >= 0)
			setlogmask(LOG_UPTO(log_upto));
	}

	if (!fflag)
		daemon(0, 0);
	
	if ((kq = kqueue()) == -1) {
		msg(LOG_ERR, __func__, "kqueue(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	if ((s = sockopen()) < 0) {
		exit(EXIT_FAILURE);
	}

	msg(LOG_NOTICE, __func__, "started%s", dflag ? " (debug output" : "");
	
	EV_SET(&change[0], s, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	nchanges = 1;
	for (;;) {
		nev = kevent(kq, change, nchanges, event, COUNT_OF(event), NULL);
		nchanges = 0;
		if (nev < 0) {
			msg(LOG_ERR, __func__, "kevent: %s", strerror(errno));
			exit(EXIT_FAILURE);
		} else {
			for (i = 0; i < nev; i++) {
				if (event[i].flags & EV_ERROR) {
					msg(LOG_ERR, "EV_ERROR: %s for %lu\n",
						strerror(event[i].data), event[i].ident);
					exit(EXIT_FAILURE);
				} else {
					if (event[i].ident == (uintptr_t) s) {
						nchanges = sock_input();
					} else if (event[i].ident == RDNSS_TIMER_ID &&
					  event[i].filter == EVFILT_TIMER) {
						rdnss_timer(event[i].data);
					} else if (event[i].ident == DNSSL_TIMER_ID &&
					  event[i].filter == EVFILT_TIMER) {
						dnssl_timer(event[i].data);
					}
				}
			}
		}
	}

	close(kq);
	return EXIT_SUCCESS;
}
