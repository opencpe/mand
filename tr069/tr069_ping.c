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

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>

#include <pthread.h>

#include "tr069_ping.h"

#define SDEBUG
#include "debug.h"

static inline int in_cksum(unsigned short *buf, int sz);
static inline int create_icmp_socket(void);
static unsigned long long ltime(void);

static const int DEFDATALEN = 56;
static const int MAXIPLEN = 60;
static const int MAXICMPLEN = 76;
static const int MAXPACKET = 65468;
#define		 MAX_DUP_CHK (8 * 128)
static const int MAXWAIT = 10;
static const int PINGINTERVAL = 1;              /* second */

#define O_QUIET         (1 << 0)

#define A(bit)          rcvd_tbl[(bit)>>3]      /* identify byte in array */
#define B(bit)          (1 << ((bit) & 0x07))   /* identify bit in byte */
#define SET(bit)        (A(bit) |= B(bit))
#define CLR(bit)        (A(bit) &= (~B(bit)))
#define TST(bit)        (A(bit) & B(bit))

int		ping_running = 0;
pthread_mutex_t	ping_mutex = PTHREAD_MUTEX_INITIALIZER;

/* common routines - should be in a separate C file? */

static inline int
in_cksum(unsigned short *buf, int sz)
{
        int sum = 0;
        unsigned short *w = buf;

        while (sz > 1) {
                sum += *w++;
                sz -= 2;
        }

        /* mop up an odd byte, if necessary */

	if (sz == 1)
		sum += *(unsigned char *)w;

        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        return (~sum & 0xFFFF);
}

static inline int
create_icmp_socket(void)
{
        struct protoent *proto;
        int sock;

        proto = getprotobyname("icmp");
        /* if getprotobyname failed, just silently force
         * proto->p_proto to have the correct value for "icmp" */
        if ((sock = socket(AF_INET, SOCK_RAW,
                        (proto ? proto->p_proto : 1))) < 0) {        /* 1 == ICMP */
                return -1;
        }

        return sock;
}

static unsigned long long
ltime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int
tr069_ping(struct sockaddr_in host, unsigned int send_cnt, unsigned int timeout,
	   unsigned int *succ_cnt, unsigned int *fail_cnt, unsigned int *tavg,
	   unsigned int *tmin, unsigned int *tmax,
	   TR069_PING_CB callback, void *user_data)
{
	unsigned long long now, next;

	unsigned long	tsum = 0;
	long		ntransmitted = 0;

        struct icmp	*pkt, *inpkt;
        int		pingsock, c;
	int		myid;
        char		packet[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
        char		inpckt[DEFDATALEN + MAXIPLEN + MAXICMPLEN];
        int		ret;
	int		r = 0;

	ENTER();

	*succ_cnt = 0;
	*fail_cnt = 0;
	*tavg = 0;
	*tmin = 0;
	*tmax = 0;

        pingsock = create_icmp_socket();
        if (pingsock < 0) {
		EXIT();
                return -1;
	}

        pkt = (struct icmp *) packet;
        memset(pkt, 0, sizeof(packet));
        pkt->icmp_type = ICMP_ECHO;
        pkt->icmp_id = myid = getpid() & 0xFFFF;

	next = ltime();

        /* listen for replies */
        while (send_cnt) {
		struct pollfd pfd;
                struct sockaddr_in from;
                size_t fromlen = sizeof(from);

		(*fail_cnt) = ntransmitted - (*succ_cnt);
		now = ltime();

		debug("(): ping: now: %llu, next: %llu\n", now, next);
		if (next < now) {
			next = now + timeout;

			pkt->icmp_seq = htons(++ntransmitted);
			gettimeofday((struct timeval *) &packet[8], NULL);
			pkt->icmp_cksum = 0;
			pkt->icmp_cksum = in_cksum((unsigned short *) pkt, sizeof(packet));

			c = sendto(pingsock, packet, sizeof(packet), 0, &host, sizeof(host));
			send_cnt--;

			if (c < 0) {
				debug("(): sendto: %d, %s\n", c, strerror(errno));
				usleep(timeout * 1000);
				(*fail_cnt)++;
				continue;
			}

			if (c != sizeof(packet)) {
				r = -1;
				break;
			}
		}

		pfd.fd = pingsock;
		pfd.events = POLLIN | POLLPRI;
		ret = poll(&pfd, 1, timeout);

		debug("(): poll: %d, %d\n", ret, pfd.revents);
		if (ret == 1 && !(pfd.revents & ~(POLLIN | POLLPRI))) {
                        if ((c = recvfrom(pingsock, inpckt, sizeof(inpckt), 0,
                                          (struct sockaddr *) &from, &fromlen)) < 0) {
                                if (errno == EINTR)
                                        continue;
				debug("(): recvfrom: %d, %s\n", c, strerror(errno));
				continue;
                        }

			if (host.sin_addr.s_addr != from.sin_addr.s_addr)
				continue;

                        if (c >= 76) {                  /* ip + icmp */
                                struct iphdr *iphdr = (struct iphdr *) inpckt;

                                inpkt = (struct icmp *) (inpckt + (iphdr->ihl << 2));     /* skip ip hdr */
                                if (inpkt->icmp_type == ICMP_ECHOREPLY) {
					struct timeval tv, *tp;
					unsigned long triptime;

                                        (*succ_cnt)++;

					gettimeofday(&tv, NULL);
					tp = (struct timeval *) inpkt->icmp_data;

					if ((tv.tv_usec -= tp->tv_usec) < 0) {
						--tv.tv_sec;
						tv.tv_usec += 1000000;
					}
					tv.tv_sec -= tp->tv_sec;

					triptime = tv.tv_sec * 1000 + tv.tv_usec / 1000;
					tsum += triptime;
					*tavg = tsum / *succ_cnt;
					if (!*tmin || triptime < *tmin)
						*tmin = triptime;
					if (triptime > *tmax)
						*tmax = triptime;

					if (callback &&
					    (r = callback(user_data, c, from.sin_addr, ntohs(inpkt->icmp_seq), triptime)))
						break;
				}
                        }
                }
        }

        close(pingsock);
	(*fail_cnt) = ntransmitted - (*succ_cnt);

	EXIT();
	return r;
}
