/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include <pthread.h>

#include "tr069_trace.h"

#define SDEBUG
#include "debug.h"

#define	HDLEN	28

static inline void clearmsg(void);
static inline void blockuntil(int fd, unsigned int msec);
static inline void genpkg(char *buf, unsigned int ttl);
static inline int getrtt(int ps, char *buf);
static inline enum tr069_trace_state parseerr(int *rtt, char *hostname,
					      struct in_addr *ip);
static inline enum tr069_trace_state dohop(unsigned int ttl, int payload, int port,
					   unsigned int timeout, int *rtt,
					   char *hostname, struct in_addr *ip);
static inline enum tr069_trace_state mainloop(unsigned int ctries, unsigned int timeout,
					      unsigned int blksize, unsigned int mxhpcnt,
					      TR069_TRACE_CB callback, void *user_data);
static inline int initsock(void);
static inline int initmsg(unsigned int blksize);
static inline void freemsg(void);

static unsigned int		last_time;

static struct sockaddr_in	traceaddr;
static struct msghdr		msg;
static struct iovec		msg_iov;
static int			sock;

int		trace_running = 0;
pthread_mutex_t	trace_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MAX_HOSTNAME_LEN 256

static inline void
clearmsg(void)
{
	msg.msg_flags = 0;
	msg.msg_controllen = 0x0200;
}

static inline void
blockuntil(int fd, unsigned int msec)
{
	struct pollfd pfd;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;
	poll(&pfd, 1, msec);
}

static inline void
genpkg(char *buf, unsigned int ttl)
{
	struct timeval tv;
	unsigned int *pkg = (unsigned int*) buf;

	pkg[0] = ttl;

	gettimeofday(&tv, NULL);
	last_time = (unsigned int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
	pkg[1] = last_time;

}

static inline int
getrtt(int ps, char *buf)
{
	struct timeval tv;
	unsigned int t, *pkg = (unsigned int*) buf;

	gettimeofday(&tv, NULL);
	t = (unsigned int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
	if (ps >= 2 * sizeof(int))
		return (int)(t - pkg[1]);
	return (int)(t - last_time);
}

static inline enum tr069_trace_state
parseerr(int *rtt, char *hostname, struct in_addr *ip)
{
	int res = -1;
	struct cmsghdr *cmsg;
	struct sock_extended_err *se;
	struct sockaddr_in *hopper;

	for (;;) {
		do {
			clearmsg();
			res = recvmsg(sock, &msg, MSG_ERRQUEUE);
			if (res < 0 && errno == EAGAIN)
				return tr069_trace_no_reply;
		} while (res < 0);

		se = NULL;

		*rtt = getrtt(res, msg.msg_iov->iov_base);
		debug("(): triptime = %ums\n", *rtt);

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
			if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR)
				se = (struct sock_extended_err *) CMSG_DATA(cmsg);
			else
				debug("(): cmsg_level: %d, cmsg_type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);

		if (!se) {
			debug("(): no info\n");
			return tr069_trace_error;
		}

		if (se->ee_origin == SO_EE_ORIGIN_LOCAL) {
			debug("(): [LOCALHOST]\n");
		} else if (se->ee_origin == SO_EE_ORIGIN_ICMP) {
			hopper = (struct sockaddr_in*)SO_EE_OFFENDER(se);

			debug("(): IP = 0x%08X\n", hopper->sin_addr.s_addr);
			ip->s_addr = hopper->sin_addr.s_addr;

			if (!getnameinfo(SO_EE_OFFENDER(se), sizeof(struct sockaddr_in),
					 hostname, MAX_HOSTNAME_LEN, NULL, 0, NI_NAMEREQD)) {
				debug("(): hostname = %s\n", hostname);
			}
		}

		switch (se->ee_errno) {
		case ETIMEDOUT:
			break;
		case ECONNREFUSED: //DONE!!!
			return tr069_trace_done;
		case EHOSTUNREACH:
			if (se->ee_origin == SO_EE_ORIGIN_ICMP &&
			    se->ee_type == 11 && se->ee_code == 0)
				return tr069_trace_hop;
			return tr069_trace_stuck;
		case EPROTO:
		case ENETUNREACH:
		case EACCES:
			return tr069_trace_error;
		default:
			errno = se->ee_errno;
			return tr069_trace_error;
		}
	}

	/* not reached */

	return tr069_trace_error;
}

static inline enum tr069_trace_state
dohop(unsigned int ttl, int payload, int port, unsigned int timeout,
      int *rtt, char *hostname, struct in_addr *ip)
{
	int i, x = -1;
	char buffer[payload];

	memset(buffer, 0, payload);
	traceaddr.sin_port = htons(port);
	genpkg(buffer, ttl);

	for (i = 0; x < 0 && i < 7; i++)
		x = sendto(sock, buffer, payload, 0, (struct sockaddr*)&traceaddr, sizeof(traceaddr));
	if (x > 0) {
		blockuntil(sock, timeout);
		if (recv(sock, buffer, payload, MSG_DONTWAIT) > 0)
			return tr069_trace_hop;
		return parseerr(rtt, hostname, ip);
	}

	return tr069_trace_error;
}

static inline enum tr069_trace_state
mainloop(unsigned int ctries, unsigned int timeout, unsigned int blksize,
	 unsigned int mxhpcnt, TR069_TRACE_CB callback, void *user_data)
{
	int			run = 1;
	enum tr069_trace_state	state;

	for (unsigned int ttl = 1; run && ttl <= mxhpcnt; ttl++) {
		debug("(): HOP: %i\n", ttl);
		if (setsockopt(sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl))) {
			debug("(): IP_TTL\n");
			return tr069_trace_error;
		}

		for (unsigned int tries = 0; tries < ctries; tries++) {
			char		hostname[MAX_HOSTNAME_LEN] = {'\0'};
			struct in_addr	ip = {.s_addr = 0};
			int		rtt = -1;

			state = dohop(ttl, blksize, TRACEROUTE_STDPORT + ttl - 1,
				      timeout, &rtt, hostname, &ip);

			if (callback &&
			    callback(user_data, state, ttl, *hostname ? hostname : NULL, ip, rtt)) {
				state = tr069_trace_abort;
				break;
			}

			if (state > tr069_trace_error)
				break;
		}

		switch (state) {
		case tr069_trace_no_reply:
			debug("(): pkt lost\n");
			break;
		case tr069_trace_error:
			debug("(): err\n");
			break;
		case tr069_trace_hop:
			debug("(): hop\n");
			break;
		case tr069_trace_done:
			debug("(): dest\n");
			run = 0;
			break;
		case tr069_trace_stuck:
			debug("(): stuck\n");
			run = 0;
			break;
		case tr069_trace_abort:
			debug("(): aborted\n");
			run = 0;
			break;
		default:
			debug("(): weird err\n");
			run = 0;
		}
	}

	switch (state) {
	case tr069_trace_no_reply:
		debug("(): lost trace\n");
		break;
	case tr069_trace_hop:
		debug("(): too many hops\n");
		break;
	case tr069_trace_done:
		debug("(): done\n");
		break;
	case tr069_trace_abort:
		debug("(): aborted\n");
		break;
	case tr069_trace_error:
	case tr069_trace_stuck:
	default:
		debug("(): given up\n");
	}

	return state;
}

static inline int
initsock(void)
{
	int one = 1;

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		debug("(): cannot create socket\n");
		return -1;
	}

	if (setsockopt(sock, SOL_IP, IP_RECVERR, &one, sizeof(one))) {
		debug("(): IP_RECVERR\n");
		close(sock);
		return -1;
	}

	return 0;
}

static inline int
initmsg(unsigned int blksize)
{
	msg.msg_iovlen = 1;
	msg.msg_iov = &msg_iov;
	msg.msg_iov->iov_len = blksize;
	msg.msg_name = &traceaddr;
	msg.msg_namelen = sizeof(traceaddr);
	clearmsg();

	if (!(msg.msg_control = malloc(msg.msg_controllen)) ||
	    !(msg.msg_iov->iov_base = malloc(blksize))) {
		free(msg.msg_control);
	    	return -1;
	}

	return 0;
}

static inline void
freemsg(void)
{
	free(msg.msg_iov->iov_base);
	free(msg.msg_control);
}

enum tr069_trace_state
tr069_trace(struct sockaddr_in host, unsigned int tries, unsigned int timeout,
	    unsigned int blksize, unsigned int mxhpcnt,
	    TR069_TRACE_CB callback, void *user_data)
{
	enum tr069_trace_state r;

	ENTER();

	memcpy(&traceaddr, &host, sizeof(struct sockaddr_in));

	if (initsock()) {
		EXIT();
		return tr069_trace_error;
	}

	if (initmsg(blksize)) {
		close(sock);
		EXIT();
		return tr069_trace_error;
	}

	r = mainloop(tries, timeout, blksize, mxhpcnt, callback, user_data);

	freemsg();
	close(sock);

	EXIT();
	return r;
}

