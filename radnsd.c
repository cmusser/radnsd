#include <sys/event.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
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

typedef enum timer_type {
	RDNSS_TIMER = 0,
	DNSSL_TIMER = 1
} timer_type;

struct dns_data {
	timer_type	timer_type; /* used to select list in which to search for this element */
	uintptr_t	timer_id;   /* current timer. Deleted and replaced when update arrives */
	char		str       [256]; /* domain name or server address */
	char		expiry[26]; /* For display */
			TAILQ_ENTRY   (dns_data) entries;
};

TAILQ_HEAD(radns_list_t, dns_data);
struct radns_list_t rdnss_list = TAILQ_HEAD_INITIALIZER(rdnss_list);
struct radns_list_t dnssl_list = TAILQ_HEAD_INITIALIZER(dnssl_list);

struct change_kev {
	struct kevent kev;
	TAILQ_ENTRY   (change_kev) entries;
};

TAILQ_HEAD(change_kev_list_t, change_kev);

struct event_changelist {
	int count;
	uint32_t cur_timer_id;
	struct change_kev_list_t events;
};

#define ALLROUTER "ff02::2"
static struct sockaddr_in6 sin6_allrouters = {
	sizeof(sin6_allrouters),
	AF_INET6,
	0,
	0,
	IN6ADDR_ANY_INIT,
	0
};

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))
#define ADDRCOUNT(rdnss_p) ((rdnss_p->nd_opt_rdnss_len - 1) / 2)
#define DELETE_TIMER 0

struct event_changelist changelist;
int		log_upto = LOG_NOTICE;
bool		fflag = false;
bool		dflag = false;
int		rssock;
struct msghdr	rcvmhdr;
u_char		answer  [1500];
struct iovec	rcviov[1];
static struct sockaddr_in6 from;
char		ifname[IFNAMSIZ];

void		usage(void);
void		log_msg   (int priority, const char *func, const char *msg,...);
struct dns_data  *find_radns_by_str(struct radns_list_t *list, char *str);
void		changelist_init(struct event_changelist *list, int s);
bool		changelist_set_timer(struct event_changelist *list, struct dns_data *data, intptr_t timeout);
int		changelist_event_listen(int kq, struct event_changelist *list, struct kevent *event);
int		sockopen   (void);
void		process_rdnss_opt(uint16_t ra_ltime, struct nd_opt_rdnss *rdnss_p);
void		process_dnssl_opt(uint16_t ra_ltime, struct nd_opt_dnssl *dnssl_p);
void		sock_input (void);
void		write_resolv_conf(char *ifname);
void		expire_timer(struct kevent *kev);
size_t		get_max_width(struct radns_list_t *list, size_t max);
void		dump_state(void);

void
usage(void)
{
	fprintf(stderr, "usage: radnsd [-fdh]\n");
	exit(EXIT_FAILURE);
}

void
log_msg(int priority, const char *func, const char *msg,...)
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

struct dns_data *
find_radns_by_str(struct radns_list_t *list, char *str)
{
	struct dns_data *cur;

	TAILQ_FOREACH(cur, list, entries) {
		if (strcmp(cur->str, str) == 0)
			return cur;
	}

	return NULL;
}

void
changelist_init(struct event_changelist *list, int s)
{
	struct change_kev *change;

	list->cur_timer_id = 0;
	TAILQ_INIT(&list->events);
	list->count = 2;
	change = calloc(sizeof(struct change_kev), 1);
	EV_SET(&change->kev, s, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	TAILQ_INSERT_TAIL(&list->events, change, entries);
	change = calloc(sizeof(struct change_kev), 1);
	EV_SET(&change->kev, SIGUSR1, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);
	TAILQ_INSERT_TAIL(&list->events, change, entries);
}

bool
changelist_set_timer(struct event_changelist *list, struct dns_data *data, intptr_t timeout)
{
	bool rv = true;
	struct change_kev *change;

	change = calloc(sizeof(struct change_kev), 1);
	if (change == NULL) {
		log_msg(LOG_ERR, __func__, "malloc for timer change event failed");
		rv = false;
	} else {
		list->count++;
		EV_SET(&change->kev, data->timer_id, EVFILT_TIMER,
		    (timeout == DELETE_TIMER) ? EV_DELETE
		    : (EV_ADD | EV_ENABLE | EV_ONESHOT),
		    0, timeout, data);
		TAILQ_INSERT_TAIL(&list->events, change, entries);
	}

	return rv;
}

int
changelist_event_listen(int kq, struct event_changelist *list, struct kevent *event) {
	int nev, i;
	struct kevent *changes;
	struct change_kev *change;

	changes = calloc(sizeof(struct kevent), list->count);
	if (changes == NULL) {
		nev = 0;
		log_msg(LOG_ERR, __func__, "malloc for kevent array failed");
	} else {
		i = 0;
		TAILQ_FOREACH(change, &list->events, entries)
			changes[i++] = change->kev;

		nev = kevent(kq, changes, list->count, event, 1, NULL);
		free(changes);
	}

	list->count = 0;
	while (!TAILQ_EMPTY(&list->events)) {
		change = TAILQ_FIRST(&list->events);
		TAILQ_REMOVE(&list->events, change, entries);
		free(change);
	}

	return nev;
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
		log_msg(LOG_ERR, __func__,
			"malloc for receive msghdr failed");
		return (-1);
	}
	memset(&sin6_allrouters, 0, sizeof(struct sockaddr_in6));
	sin6_allrouters.sin6_family = AF_INET6;
	sin6_allrouters.sin6_len = sizeof(sin6_allrouters);
	if (inet_pton(AF_INET6, ALLROUTER,
		      &sin6_allrouters.sin6_addr.s6_addr) != 1) {
		log_msg(LOG_ERR, __func__, "inet_pton failed for %s",
			ALLROUTER);
		return (-1);
	}
	if ((rssock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		log_msg(LOG_ERR, __func__, "socket: %s", strerror(errno));
		return (-1);
	}
	/* Return receiving interface */
	on = 1;
	if (setsockopt(rssock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0) {
		log_msg(LOG_ERR, __func__, "IPV6_RECVPKTINFO: %s",
			strerror(errno));
		exit(1);
	}
	/* Accept only router advertisements on the socket */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	if (setsockopt(rssock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		       sizeof(filt)) == -1) {
		log_msg(LOG_ERR, __func__, "setsockopt(ICMP6_FILTER): %s",
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
write_resolv_conf(char *ifname)
{
	FILE           *resolv_conf;
	struct dns_data *cur;
	bool		has_dnssl = false;
	char		dnssl     [256] = {'\0'};

	resolv_conf = fopen("/etc/resolv.conf", "w");
	if (resolv_conf != NULL) {
		fprintf(resolv_conf, "# from %s (RA)\n", ifname);
		TAILQ_FOREACH(cur, &dnssl_list, entries) {
			if (!has_dnssl) {
				has_dnssl = true;
				strlcpy(dnssl, "search", sizeof(dnssl));
			}
			if (strlcat(dnssl, " ", sizeof(dnssl)) <= sizeof(dnssl))
				strlcat(dnssl, cur->str, sizeof(dnssl));
		}
		fprintf(resolv_conf, "%s\n", dnssl);

		TAILQ_FOREACH(cur, &rdnss_list, entries)
			fprintf(resolv_conf, "nameserver %s\n", cur->str);

		fclose(resolv_conf);
	}
}

void
format_timestamp(char *time_str, size_t bufsz, time_t *time)
{
	struct tm time_tm;

	localtime_r(time, &time_tm);
	strftime(time_str, bufsz, "%c", &time_tm);
}


void
get_expiry_values(intptr_t *ltime, char *expiry_str, size_t bufsz, uint32_t opt_ltime,
    uint16_t ra_ltime, char *desc)
{
	time_t expire_time;

	*ltime = (intptr_t) ntohl(opt_ltime);
	if (ra_ltime < *ltime)
		*ltime = ra_ltime;

	time(&expire_time);
	expire_time += *ltime;
	format_timestamp(expiry_str, bufsz, &expire_time);
	log_msg(LOG_INFO, __func__, "%s option (lifetime: %u, expires %s)", desc, *ltime, expiry_str);
	*ltime *= 1000;
}

void
process_rdnss_opt(uint16_t ra_ltime, struct nd_opt_rdnss *rdnss)
{

	intptr_t	ltime;
	char            expiry_str[26];
	uint8_t		i;
	struct dns_data *rdnss_data;
	struct in6_addr *cur_addr_p;
	char            v6addr[INET6_ADDRSTRLEN];

	get_expiry_values(&ltime, expiry_str, sizeof(expiry_str),
	    rdnss->nd_opt_rdnss_lifetime, ra_ltime, "RDNSS");

	for (cur_addr_p = (struct in6_addr *)(rdnss + 1), i = 0;
	     i < ADDRCOUNT(rdnss);
	     i++, cur_addr_p++) {
		inet_ntop(AF_INET6, cur_addr_p, v6addr, sizeof(v6addr));
		rdnss_data = find_radns_by_str(&rdnss_list, v6addr);
		if (rdnss_data == NULL) { /* New server */
			rdnss_data = malloc(sizeof(struct dns_data));
			if (rdnss_data != NULL) {
				rdnss_data->timer_type = RDNSS_TIMER;
				rdnss_data->timer_id = ++changelist.cur_timer_id;
				strlcpy(rdnss_data->str, v6addr, sizeof(rdnss_data->str));
				strlcpy(rdnss_data->expiry, expiry_str, sizeof(rdnss_data->expiry));
				TAILQ_INSERT_TAIL(&rdnss_list, rdnss_data, entries);
				changelist_set_timer(&changelist, rdnss_data, ltime);
			}
		} else { /* Updated server */
			changelist_set_timer(&changelist, rdnss_data, DELETE_TIMER);
			if (ltime == 0)
				TAILQ_REMOVE(&rdnss_list, rdnss_data, entries);
			else {
				rdnss_data->timer_id = ++changelist.cur_timer_id;
				changelist_set_timer(&changelist, rdnss_data, ltime);
			}
		}
	}
}

void
process_dnssl_opt(uint16_t ra_ltime, struct nd_opt_dnssl *dnssl)
{
	intptr_t	ltime;
	char            expiry_str[26];
	uint8_t        *cur, prev = 0;
	bool		skip = false;
	char		label     [64];
	char		segment   [65];
	char		domain    [256] = {'\0'};
	struct dns_data *dnssl_data;

	get_expiry_values(&ltime, expiry_str, sizeof(expiry_str),
	    dnssl->nd_opt_dnssl_lifetime, ra_ltime, "DNSSL");

	cur = (uint8_t *) (dnssl + 1);
	while (!(*cur == 0 && prev == 0)) {

		if (*cur == 0) {
			/* The end of a series of labels. */
			if (!skip) {
				dnssl_data = find_radns_by_str(&dnssl_list, domain);
				if (dnssl_data == NULL) { /* New domain */
					dnssl_data = malloc(sizeof(struct dns_data));
					if (dnssl_data != NULL) {
						dnssl_data->timer_type = DNSSL_TIMER;
						dnssl_data->timer_id = ++changelist.cur_timer_id;
						strlcpy(dnssl_data->str, domain, sizeof(dnssl_data->str));
						strlcpy(dnssl_data->expiry, expiry_str, sizeof(dnssl_data->expiry));
						TAILQ_INSERT_TAIL(&dnssl_list, dnssl_data, entries);
						changelist_set_timer(&changelist, dnssl_data, ltime);
					}
				} else { /* Updated domain */
					changelist_set_timer(&changelist, dnssl_data, DELETE_TIMER);
					if (ltime == 0)
						TAILQ_REMOVE(&dnssl_list, dnssl_data, entries);
					else {
						dnssl_data->timer_id = ++changelist.cur_timer_id;
						changelist_set_timer(&changelist, dnssl_data, ltime);
					}

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
					log_msg(LOG_ERR, __func__, "domain \"%s\" too long, skipping", domain);
				}
			} else {
				skip = true;
				log_msg(LOG_ERR, __func__, "label \"%s\" too long, skipping domain", label);
			}
		}
		/*
		 * Advance to the next label, regardless of whether the
		 * current one was processed.
		 */
		prev = *cur;
		cur += (*cur + 1);
	}
}

void
sock_input(void)
{
 	int		i;
	struct nd_router_advert *ra;
	uint16_t	ra_ltime;
	time_t		now;
	char		now_str[26];
	char           *cur, *end;
	struct nd_opt_hdr *opt;
	int ifindex = 0;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;

	if ((i = recvmsg(rssock, &rcvmhdr, 0)) < 0) {
		log_msg(LOG_ERR, __func__, "recvmsg: %s", strerror(errno));
		return;
	}

	ra = rcviov[0].iov_base;
	ra_ltime = ntohs(ra->nd_ra_router_lifetime);
	time(&now);
	format_timestamp(now_str, sizeof(now_str),  &now);
	log_msg(LOG_INFO, __func__, "RA received at %s (lifetime: %lu)",
		now_str, ra_ltime);

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
			process_rdnss_opt(ra_ltime, (struct nd_opt_rdnss *)opt);
			break;
		case ND_OPT_DNSSL:
			process_dnssl_opt(ra_ltime, (struct nd_opt_dnssl *)opt);
			break;
		default:
			log_msg(LOG_WARNING, __func__, "unrecognized message: %d",
				opt->nd_opt_type);
		}
		cur += (opt->nd_opt_len * 8);
	}

	for (cm = (struct cmsghdr *)CMSG_FIRSTHDR(&rcvmhdr);
	     cm;
	     cm = (struct cmsghdr *)CMSG_NXTHDR(&rcvmhdr, cm)) {
		if (cm->cmsg_level == IPPROTO_IPV6 &&
		    cm->cmsg_type == IPV6_PKTINFO &&
		    cm->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
			pi = (struct in6_pktinfo *)(CMSG_DATA(cm));
			ifindex = pi->ipi6_ifindex;
		}
	}

	if (ifindex == 0)
		strlcpy(ifname, "unknown", sizeof(ifname));
	else
		if_indextoname(pi->ipi6_ifindex, ifname);


	if (changelist.count > 0)
		write_resolv_conf(ifname);
}

void
expire_timer(struct kevent *kev)
{
	struct dns_data *data;
	time_t now;
	char expired_at[26];

	data = kev->udata;
	time(&now);
	format_timestamp(expired_at, sizeof(expired_at), &now);
	log_msg(LOG_INFO, __func__, "timer %u for %s expired at %s",
	    data->timer_id, data->str, expired_at);
	TAILQ_REMOVE(data->timer_type == RDNSS_TIMER ? &rdnss_list : &dnssl_list,
	    data, entries);
	write_resolv_conf(ifname);
}

size_t
get_max_width(struct radns_list_t *list, size_t max)
{
	size_t cur;
	struct dns_data *data;

	TAILQ_FOREACH(data, list, entries) {
		cur = strlen(data->str);
		if (cur > max)
			max = cur;
	}

	return max;
}

void
dump_state(void)
{
	size_t max;
	struct dns_data *data;
	char fmt[16];

	max = get_max_width(&rdnss_list, 0);
	max = get_max_width(&dnssl_list, max);
	snprintf(fmt, sizeof(fmt), "%%-%lus  %%s", max);
	log_msg(LOG_ERR, __func__, "servers:");
	TAILQ_FOREACH(data, &rdnss_list, entries)
	     log_msg(LOG_NOTICE, __func__, fmt, data->str, data->expiry);
	log_msg(LOG_ERR, __func__, "domains:");
	TAILQ_FOREACH(data, &dnssl_list, entries)
	    log_msg(LOG_NOTICE, __func__, fmt, data->str, data->expiry);
}

int
main(int argc, char *argv[])
{
	struct kevent	event;
	int		ch, kq, s, nev;
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

	signal(SIGUSR1, SIG_IGN);

	if (!fflag)
		daemon(0, 0);

	if ((kq = kqueue()) == -1) {
		log_msg(LOG_ERR, __func__, "kqueue(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((s = sockopen()) < 0)
		exit(EXIT_FAILURE);

	log_msg(LOG_NOTICE, __func__, "started%s", dflag ? " (debug output)" : "");

	changelist_init(&changelist, s);
	for (;;) {
		nev = changelist_event_listen(kq, &changelist, &event);
		if (nev < 0) {
			log_msg(LOG_ERR, __func__, "kevent: %s", strerror(errno));
			exit(EXIT_FAILURE);
		} else {
			if (event.flags & EV_ERROR) {
				log_msg(LOG_ERR, __func__, "EV_ERROR: %s for %lu",
				    strerror(event.data), event.ident);
				exit(EXIT_FAILURE);
			} else {
				switch (event.filter) {
				case EVFILT_READ:
					sock_input();
					break;
				case EVFILT_TIMER:
					expire_timer(&event);
					break;
				case EVFILT_SIGNAL:
					dump_state();
					break;
				default:
					log_msg(LOG_WARNING, __func__, "unhandled event type: %d",
					    event.filter);
				}
			}
		}
	}

	close(kq);
	return EXIT_SUCCESS;
}
