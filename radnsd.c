#include <sys/event.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <resolv.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifdef SHORT_TEST_STRINGS
#define LABEL_MAX 6
#define DOMAIN_MAX 16
#else
#define LABEL_MAX 64
#define DOMAIN_MAX 256
#endif

#define DNS_STR_MAX 256
#define DATE_MAX 26

#define PID_FILE "/var/run/radnsd.pid"
#define RESOLVCONF_FILE "/etc/resolv.conf"

struct dns_data {

	u_int8_t	type;	/* List to which this element belongs */
	uintptr_t	timer_id;	/* Replaced when update arrives */
	char		str       [DNS_STR_MAX];	/* domain name or server
							 * address */
	time_t		expiry;
			TAILQ_ENTRY   (dns_data) entries;
};

TAILQ_HEAD(dns_data_list, dns_data);

struct radns_list {
	uint8_t		type;
	struct dns_data_list list;
	int		max;
	struct dns_data *last;
};

struct change_kev {
	struct kevent	kev;
			TAILQ_ENTRY   (change_kev) entries;
};

TAILQ_HEAD(change_kev_list, change_kev);

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

struct radns_list servers = {ND_OPT_RDNSS, TAILQ_HEAD_INITIALIZER(servers.list), MAXNS, NULL};
struct radns_list search_domains = {ND_OPT_DNSSL, TAILQ_HEAD_INITIALIZER(search_domains.list), MAXDNSRCH, NULL};
int		changelist_count;
uint32_t	changelist_cur_timer_id;
struct change_kev_list changelist_events;
int		log_upto;
bool		fflag = false;
int		dflag = 0;
int		rssock;
struct msghdr	rcvmhdr;
u_char		answer  [1500];
struct iovec	rcviov[1];
static struct sockaddr_in6 from;
char		ifname    [IFNAMSIZ];

void		usage     (void);
void		log_msg   (int priority, const char *msg,...);
void		changelist_init(int s);
bool		changelist_add_timer_kev(struct dns_data *data, intptr_t timeout_sec);
int		changelist_event_listen(int kq, struct kevent *event);
int		sockopen   (void);
void		format_timestamp(char *time_str, size_t bufsz, time_t time);
time_t		get_expiry(time_t ltime);
time_t		get_ltime(struct nd_router_advert *ra, struct nd_opt_hdr *opt);
void		handle_dns_data(struct radns_list *radns, char *str, uintptr_t ltime);
void		prepend_new_dns_data(u_int8_t type);
bool		validate_label(u_int8_t * label, u_int8_t len);
void		process_rdnss_opt(struct nd_router_advert *ra, struct nd_opt_hdr *opt);
void		process_dnssl_opt(struct nd_router_advert *ra, struct nd_opt_hdr *opt);
void		sock_input(void);
void		write_resolv_conf(char *ifname);
void		expire_timer(struct kevent *kev);
size_t		get_max_width(struct radns_list *list, size_t max);
void		dump_state(void);

void
usage(void)
{
	fprintf(stderr, "usage: radnsd [-fdh]\n");
	exit(EXIT_FAILURE);
}

void
log_msg(int priority, const char *msg,...)
{
	va_list		ap;

	va_start(ap, msg);
	if (fflag) {
		if (priority <= log_upto) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, "\n");
		}
	} else {
		vsyslog(priority, msg, ap);
	}
	va_end(ap);
}

void
changelist_init(int s)
{
	struct change_kev *change;

	changelist_cur_timer_id = 0;
	TAILQ_INIT(&changelist_events);
	changelist_count = 2;
	change = calloc(sizeof(struct change_kev), 1);
	EV_SET(&change->kev, s, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	TAILQ_INSERT_TAIL(&changelist_events, change, entries);
	change = calloc(sizeof(struct change_kev), 1);
	EV_SET(&change->kev, SIGUSR1, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);
	TAILQ_INSERT_TAIL(&changelist_events, change, entries);
}

bool
changelist_add_timer_kev(struct dns_data *data, intptr_t timeout_sec)
{
	bool		ok = true;
	struct change_kev *change;
	u_short		flags;
	char           *desc;

	change = calloc(sizeof(struct change_kev), 1);
	if (change == NULL) {
		log_msg(LOG_ERR, "malloc for timer change event failed");
		ok = false;
	} else {
		changelist_count++;
		if (timeout_sec == DELETE_TIMER) {
			flags = EV_DELETE;
			desc = "delete";
		} else {
			flags = (EV_ADD | EV_ENABLE | EV_ONESHOT);
			desc = "add";
			data->timer_id = ++changelist_cur_timer_id;
		}
		EV_SET(&change->kev, data->timer_id, EVFILT_TIMER, flags,
		       0, (timeout_sec * 1000), data);
		TAILQ_INSERT_TAIL(&changelist_events, change, entries);
		log_msg(LOG_DEBUG, "%s timer %lu", desc, change->kev.ident);
	}

	return ok;
}

int
changelist_event_listen(int kq, struct kevent *event)
{
	int		nev       , i;
	struct kevent  *changes;
	struct change_kev *change, *change_tmp;

	changes = calloc(sizeof(struct kevent), changelist_count);
	if (changes == NULL) {
		nev = 0;
		log_msg(LOG_ERR, "malloc for kevent array failed");
	} else {
		i = 0;
		TAILQ_FOREACH_MUTABLE(change, &changelist_events, entries, change_tmp) {
			changes[i++] = change->kev;
			TAILQ_REMOVE(&changelist_events, change, entries);
			free(change);
		}

		nev = kevent(kq, changes, changelist_count, event, 1, NULL);
		free(changes);
	}
	changelist_count = 0;

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
		log_msg(LOG_ERR,
			"malloc for receive msghdr failed");
		return (-1);
	}
	memset(&sin6_allrouters, 0, sizeof(struct sockaddr_in6));
	sin6_allrouters.sin6_family = AF_INET6;
	sin6_allrouters.sin6_len = sizeof(sin6_allrouters);
	if (inet_pton(AF_INET6, ALLROUTER,
		      &sin6_allrouters.sin6_addr.s6_addr) != 1) {
		log_msg(LOG_ERR, "inet_pton failed for %s",
			ALLROUTER);
		return (-1);
	}
	if ((rssock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		log_msg(LOG_ERR, "socket: %s", strerror(errno));
		return (-1);
	}
	/* Return receiving interface */
	on = 1;
	if (setsockopt(rssock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on,
		       sizeof(on)) < 0) {
		log_msg(LOG_ERR, "IPV6_RECVPKTINFO: %s",
			strerror(errno));
		exit(1);
	}
	/* Accept only router advertisements on the socket */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	if (setsockopt(rssock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt,
		       sizeof(filt)) == -1) {
		log_msg(LOG_ERR, "setsockopt(ICMP6_FILTER): %s",
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
	char		dnssl     [DNS_STR_MAX] = {'\0'};

	resolv_conf = fopen(RESOLVCONF_FILE, "w");
	if (resolv_conf != NULL) {
		fprintf(resolv_conf, "# from %s (RA)\n", ifname);
		TAILQ_FOREACH(cur, &search_domains.list, entries) {
			if (!has_dnssl) {
				has_dnssl = true;
				strlcpy(dnssl, "search", sizeof(dnssl));
			}
			if (strlcat(dnssl, " ", sizeof(dnssl)) <= sizeof(dnssl))
				strlcat(dnssl, cur->str, sizeof(dnssl));
		}
		fprintf(resolv_conf, "%s\n", dnssl);

		TAILQ_FOREACH(cur, &servers.list, entries)
			fprintf(resolv_conf, "nameserver %s\n", cur->str);

		fclose(resolv_conf);
	} else {
		log_msg(LOG_ERR, "fopen() for %s failed %s", RESOLVCONF_FILE,
			strerror(errno));
	}
}

void
format_timestamp(char *time_str, size_t bufsz, time_t time)
{
	struct tm	time_tm;

	localtime_r(&time, &time_tm);
	strftime(time_str, bufsz, "%c", &time_tm);
}

time_t
get_expiry(time_t ltime)
{
	time_t		expiry;

	time(&expiry);
	return expiry + ltime;
}

time_t
get_ltime(struct nd_router_advert *ra, struct nd_opt_hdr *opt)
{
	char           *desc;
	intptr_t	ltime , expiry;
	u_int16_t	ra_ltime;
	char		expiry_str[DATE_MAX];

	if (opt->nd_opt_type == ND_OPT_RDNSS) {
		desc = "RDNSS";
		ltime = (intptr_t) ntohl(((struct nd_opt_rdnss *)opt)->nd_opt_rdnss_lifetime);
	} else {
		desc = "DNSSL";
		ltime = (intptr_t) ntohl(((struct nd_opt_dnssl *)opt)->nd_opt_dnssl_lifetime);
	}
	/*
	 * The option lifetime is limited by the lifetime of the enclosing
	 * RA.
	 */
	ra_ltime = ntohs(ra->nd_ra_router_lifetime);
	if (ra_ltime < ltime)
		ltime = ra_ltime;

	expiry = get_expiry(ltime);

	format_timestamp(expiry_str, sizeof(expiry_str), expiry);
	log_msg(LOG_INFO, "%s option (lifetime: %u, expires %s)",
		desc, ltime, expiry_str);

	return ltime;
}

void
handle_dns_data(struct radns_list *radns, char *str, uintptr_t ltime)
{
	struct dns_data_list *list;
	struct dns_data *data, *cur, *expires_first;
	int		count;
	bool		ok = true;


	list = &radns->list;

	data = NULL;
	TAILQ_FOREACH(cur, list, entries) {
		if (strcmp(cur->str, str) == 0)
			data = cur;
	}

	if (data == NULL) {	/* New data */
		/*
		 * Server may send new entries with 0 lifetime. These should
		 * be ignored.
		 */
		if (ltime != 0) {
			data = malloc(sizeof(struct dns_data));
			if (data != NULL) {
				if (changelist_add_timer_kev(data, ltime)) {
					ok = true;
					count = 0;
					expires_first = NULL;
					TAILQ_FOREACH(cur, list, entries) {
						count++;
						if (expires_first == NULL || expires_first->expiry > cur->expiry)
							expires_first = cur;
					}

					if (count == radns->max) {
						ok = changelist_add_timer_kev(expires_first, DELETE_TIMER);
						if (ok) {
							log_msg(LOG_INFO, "evicting %s", expires_first->str);
							TAILQ_REMOVE(list, expires_first, entries);
							free(expires_first);
						}
					}
					data->type = radns->type;
					strlcpy(data->str, str, sizeof(data->str));
					data->expiry = get_expiry(ltime);
					if (radns->last == NULL)
						TAILQ_INSERT_HEAD(list, data, entries);
					else
						TAILQ_INSERT_AFTER(list, radns->last, data, entries);
					radns->last = data;
				}
			} else {
				log_msg(LOG_ERR, "failed to allocate storage for \"%s\"", str);
			}
		}
	} else {		/* Updated data */
		if (changelist_add_timer_kev(data, DELETE_TIMER)) {
			if (ltime == 0) {
				TAILQ_REMOVE(list, data, entries);
				free(data);
			} else if (changelist_add_timer_kev(data, ltime))
				data->expiry = get_expiry(ltime);
		}
		radns->last = data;
	}
}

bool
validate_label(u_int8_t * label, u_int8_t len)
{
	u_int8_t       *end;

	if (!isalpha(*label)) {
		log_msg(LOG_ERR, "first char in label (\"%c\") not a letter", *label);
		return (false);
	}
	if (len > 1) {
		end = label + len - 1;
		for (label++; label < end; label++)
			if (!(isalpha(*label) || isdigit(*label) || *label == '-')) {
				log_msg(LOG_ERR, "interior char in label (\"%c\") "
				   "not a letter, digit or hyphen", *label);
				return false;
			}
		if (!(isalpha(*label) || isdigit(*label))) {
			log_msg(LOG_ERR, "interior char in label (\"%c\") "
				"not a letter or digit", *label);
			return false;
		}
	}
	return true;
}

void
process_rdnss_opt(struct nd_router_advert *ra, struct nd_opt_hdr *opt)
{

	intptr_t	ltime;
	struct nd_opt_rdnss *rdnss;
	u_int8_t	i;
	struct in6_addr *cur_addr_p;
	char		v6addr    [INET6_ADDRSTRLEN];

	ltime = get_ltime(ra, opt);

	rdnss = (struct nd_opt_rdnss *)opt;
	for (cur_addr_p = (struct in6_addr *)(rdnss + 1), i = 0;
	     i < ADDRCOUNT(rdnss);
	     i++, cur_addr_p++) {
		inet_ntop(AF_INET6, cur_addr_p, v6addr, sizeof(v6addr));
		handle_dns_data(&servers, v6addr, ltime);
	}
}

void
process_dnssl_opt(struct nd_router_advert *ra, struct nd_opt_hdr *opt)
{
	intptr_t	ltime;
	struct nd_opt_dnssl *dnssl;
	u_int8_t       *cur_in, *in_buf_end;
	char		domain    [DOMAIN_MAX] = {'\0'};
	char           *cur_out, *domain_end;

	ltime = get_ltime(ra, opt);

	dnssl = (struct nd_opt_dnssl *)opt;
	cur_in = (u_int8_t *) (dnssl + 1);
	in_buf_end = (u_int8_t *) (dnssl + (dnssl->nd_opt_dnssl_len * 8));
	cur_out = domain;
	domain_end = domain + sizeof(domain) - 1;

	while (*cur_in != '\0' && cur_in <= in_buf_end) {
		if (*cur_in <= LABEL_MAX && (cur_out + *cur_in) < (domain_end - 1)) {
			if (validate_label(cur_in + 1, *cur_in)) {
				memcpy(cur_out, cur_in + 1, *cur_in);
				cur_out += (*cur_in);
				cur_in += (*cur_in + 1);

				if (*cur_in == '\0') {	/* Last label, create a
							 * DNSSL entry */
					handle_dns_data(&search_domains, domain, ltime);
					bzero(domain, sizeof(domain));
					cur_out = domain;
					cur_in++;
					continue;
				} else {	/* End of label, add a dot. */
					*cur_out = '.';
					cur_out++;
					continue;
				}
			}
		} else {
			log_msg(LOG_ERR, "exceeded max size for label (%d) "
				"or domain (%d)", LABEL_MAX, DOMAIN_MAX);
		}
		do {
			cur_in++;
		} while (*cur_in != '\0');
		cur_in++;
	}
}

void
sock_input(void)
{
	int		i;
	struct nd_router_advert *ra;
	time_t		now;
	char		now_str   [DATE_MAX];
	char           *cur, *end;
	struct nd_opt_hdr *opt;
	int		ifindex = 0;
	struct cmsghdr *cm;
	struct in6_pktinfo *pi = NULL;
	u_int8_t	opt_len;

	if ((i = recvmsg(rssock, &rcvmhdr, 0)) < 0) {
		log_msg(LOG_ERR, "recvmsg: %s", strerror(errno));
		return;
	}
	ra = rcviov[0].iov_base;
	time(&now);
	format_timestamp(now_str, sizeof(now_str), now);
	log_msg(LOG_INFO, "RA received at %s (lifetime: %lu)",
		now_str, ntohs(ra->nd_ra_router_lifetime));

	end = rcviov[0].iov_base + i;
	cur = (char *)(ra + 1);
	servers.last = NULL;
	search_domains.last = NULL;

	while (cur < end) {
		opt = (struct nd_opt_hdr *)cur;
		switch (opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
		case ND_OPT_PREFIX_INFORMATION:
		case ND_OPT_REDIRECTED_HEADER:
		case ND_OPT_MTU:
		case ND_OPT_ROUTE_INFO:
			/* Recognized, but not relevant */
			break;
		case ND_OPT_RDNSS:
			process_rdnss_opt(ra, opt);
			break;
		case ND_OPT_DNSSL:
			process_dnssl_opt(ra, opt);
			break;
		default:
			log_msg(LOG_WARNING, "unrecognized message: %d",
				opt->nd_opt_type);
		}
		opt_len = opt->nd_opt_len * 8;
		if (opt_len > 0)
			cur += opt_len;
		else {
			/*
			 * Don't spin in place. Zero length options are
			 * invalid.
			 */
			log_msg(LOG_WARNING, "stopping at zero-length option");
			break;
		}
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


	if (changelist_count > 0)
		write_resolv_conf(ifname);
}

void
expire_timer(struct kevent *kev)
{
	struct dns_data *data;
	time_t		now;
	char		expired_at[DATE_MAX];

	data = kev->udata;
	time(&now);
	format_timestamp(expired_at, sizeof(expired_at), now);
	log_msg(LOG_INFO, "timer %u for %s expired at %s",
		data->timer_id, data->str, expired_at);
	TAILQ_REMOVE(data->type == ND_OPT_RDNSS ? &servers.list : &search_domains.list,
		     data, entries);
	free(data);
	write_resolv_conf(ifname);
}

size_t
get_max_width(struct radns_list *radns, size_t max)
{
	size_t		cur;
	struct dns_data *data;

	TAILQ_FOREACH(data, &radns->list, entries) {
		cur = strlen(data->str);
		if (cur > max)
			max = cur;
	}

	return max;
}

void
dump_state(void)
{
	size_t		max;
	struct dns_data *data;
	char		fmt       [64];
	char		expiry_str[DATE_MAX];

	max = get_max_width(&servers, 0);
	max = get_max_width(&search_domains, max);
	snprintf(fmt, sizeof(fmt), "  %%-%lus  %%s (timer %%lu)", max);
	log_msg(LOG_NOTICE, "servers:");
	TAILQ_FOREACH(data, &servers.list, entries) {
		format_timestamp(expiry_str, sizeof(expiry_str), data->expiry);
		log_msg(LOG_NOTICE, fmt, data->str, expiry_str, data->timer_id);
	}

	log_msg(LOG_ERR, "domains:");
	TAILQ_FOREACH(data, &search_domains.list, entries) {
		format_timestamp(expiry_str, sizeof(expiry_str), data->expiry);
		log_msg(LOG_NOTICE, fmt, data->str, expiry_str, data->timer_id);
	}
}

int
main(int argc, char *argv[])
{
	struct kevent	event;
	int		ch        , kq, s, nev;
	const char     *opts;
	FILE           *pid;

	opts = "dfh";

	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'd':
			dflag++;
			break;
		case 'f':
			fflag = true;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	switch (dflag) {
	case 0:
		log_upto = LOG_NOTICE;
		break;
	case 1:
		log_upto = LOG_INFO;
		break;
	default:
		log_upto = LOG_DEBUG;
	}

	if (!fflag) {
		char           *ident;
		ident = strrchr(argv[0], '/');
		if (!ident)
			ident = argv[0];
		else
			ident++;
		openlog(ident, LOG_NDELAY | LOG_PID, LOG_DAEMON);
		if (log_upto >= 0)
			setlogmask(LOG_UPTO(log_upto));
	}
	signal(SIGUSR1, SIG_IGN);

	if (!fflag)
		daemon(0, 0);

	if ((kq = kqueue()) == -1) {
		log_msg(LOG_ERR, "kqueue(): %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if ((s = sockopen()) < 0)
		exit(EXIT_FAILURE);

	pid = fopen(PID_FILE, "w");
	if (pid != NULL) {
		fprintf(pid, "%d\n", getpid());
		fclose(pid);
	} else {
		log_msg(LOG_ERR, "fopen() for %s failed %s", PID_FILE, strerror(errno));
		exit(EXIT_FAILURE);
	}

	log_msg(LOG_NOTICE, "started");

	changelist_init(s);

	for (;;) {
		nev = changelist_event_listen(kq, &event);
		if (nev < 0) {
			log_msg(LOG_ERR, "kevent: %s", strerror(errno));
			exit(EXIT_FAILURE);
		} else {
			if (event.flags & EV_ERROR) {
				log_msg(LOG_ERR, "EV_ERROR: %s for %lu",
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
					log_msg(LOG_WARNING, "unhandled event type: %d",
						event.filter);
				}
			}
		}
	}

	close(kq);
	return EXIT_SUCCESS;
}
