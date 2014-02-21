/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * __FBSDID("$FreeBSD: src/lib/libradius/radlib.c,v 1.12 2004/06/14 20:55:30 stefanf Exp $");
 */

#include "config.h"

#include <assert.h>

#include <time.h>
#include <string.h>
#include <sys/cdefs.h>
#include <byteswap.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/queue.h>

#include <ev.h>

#define EVCAST(type, member, var) (type *)(((void *)var) - offsetof(type, member))

#if __BYTE_ORDER == __BIG_ENDIAN
/* The host byte order is the same as network byte order,
   so these functions are all just identity.  */
#define ntohll(x)               (x)
#define htonll(x)               (x)

#else

#define ntohll(x)               __bswap_64(x)
#define htonll(x)               __bswap_64(x)
#endif

#if defined(HAVE_LIBPOLARSSL)
#include <polarssl/md5.h>
#include <polarssl/havege.h>

#define MD5_DIGEST_LENGTH 16
#define MD5_CTX md5_context
#define MD5Init md5_starts
#define MD5Update(ctx, inp, len) md5_update(ctx, (unsigned char *)inp, len)
#define MD5Final(md5, ctx) md5_finish(ctx, md5)

#define EVP_MAX_MD_SIZE                 (16+20) /* The SSLv3 md5+sha1 type */

#define HMAC_CTX md5_context

#define HMAC_CTX_init(ctx)
#define HMAC_CTX_cleanup(ctx)
#define	HMAC_cleanup(ctx)

#define HMAC_Init(ctx, key, keylen, hash) md5_hmac_starts(ctx, key, keylen)
#define HMAC_Update md5_hmac_update
static inline void HMAC_Final(HMAC_CTX *ctx, unsigned char *hashOut, unsigned int *outlen) {
	md5_hmac_finish(ctx, hashOut);
	if (outlen)
		(*outlen) = 16;
}

#define EVP_md5		1

extern havege_state h_state;

#elif defined(WITH_SSL)
#include <openssl/hmac.h>
#include <openssl/md5.h>
#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#elif defined(WITH_TOMCRYPT)
#include <tomcrypt.h>

#define MD5_DIGEST_LENGTH 16
#define MD5_CTX hash_state
#define MD5Init md5_init
#define MD5Update md5_process
#define MD5Final(md5, ctx) md5_done(ctx, md5)

#define EVP_MAX_MD_SIZE                 (16+20) /* The SSLv3 md5+sha1 type */
static int EVP_md5(void) {
	int r;

	r = find_hash("md5");
	if (r == -1) {
		register_hash(&md5_desc);
		r = find_hash("md5");
	}
	return r;
}

#define HMAC_CTX hmac_state

static inline void HMAC_CTX_init(hmac_state *ctx) { memset(ctx, 0, sizeof(hmac_state)); }
#define HMAC_Init(ctx, key, keylen, hash) hmac_init(ctx, hash, key, keylen)
#define HMAC_Update hmac_process
static inline void HMAC_Final(hmac_state *ctx, unsigned char *hashOut, unsigned int *outlen) {
	unsigned long len;
	hmac_done(ctx, hashOut, &len);
	(*outlen) = len;
}
static inline void HMAC_CTX_cleanup(hmac_state *ctx) { memset(ctx, 0, sizeof(hmac_state)); }
#define	HMAC_cleanup(ctx)

#endif

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#include <md5.h>
#endif

/* We need the MPPE_KEY_LEN define */
/* not on OpenWRT  #include <netgraph/ng_mppc.h> */

#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "radlib_compat.h"
#include "radlib_private.h"

unsigned int rad_auth_invalid_server_addresses;
unsigned int rad_acct_invalid_server_addresses;

static uint8_t ident;
#if defined(WITH_TOMCRYPT)
prng_state     prng;
#endif

static void	 clear_password(struct rad_packet *);
static void	 generr(struct rad_handle *, const char *, ...)
		    __printflike(2, 3);
static void	 insert_scrambled_password(struct rad_packet *, const char *);
static void	 insert_request_authenticator(struct rad_packet *, const char *);
static void	 insert_response_authenticator(struct rad_packet *, const char *);
static void	 insert_message_authenticator(struct rad_packet *, const char  *);
static int	 is_valid_response(struct rad_handle *, const char *);
static int	 put_password_attr(struct rad_packet *, int,
		    const void *, size_t);
static int	 put_raw_attr(struct rad_packet *, int,
		    const void *, size_t);

static struct rad_handle *rad_dequeue_req(struct rad_queue *, int);
static struct rad_handle *rad_dequeue_req_only(struct rad_queue *, int);
static int       rad_sendto_srv(struct rad_handle *);
static void      rad_detach_queue(struct rad_handle *);
static void      rad_detach_queue_only(struct rad_handle *);
static void      rad_queue_timeout(EV_P_ ev_timer *w, int revents);

static void      rad_close_queue(struct rad_queue *);
static void      rad_queue_start_timer(struct rad_queue *);
static void      rad_queue_stop_timer(struct rad_queue *);

static struct rad_server_node *
get_server_node(struct rad_server_node *node)
{
	node->ref_cnt++;
	return node;
}

static void
put_server_node(struct rad_server_node **np)
{
	struct rad_server_node *node;

	node = *np;
	*np = NULL;
	if (!node)
		return;

	node->ref_cnt--;
	if (node->ref_cnt == 0) {
		printf("freeing node: %p\n", node);
		free(node);
	}
}

static void
clear_password(struct rad_packet *req)
{
	if (req->pass_len != 0) {
		memset(req->pass, 0, req->pass_len);
		req->pass_len = 0;
	}
	req->pass_pos = 0;
}

static void
generr(struct rad_handle *h, const char *format, ...)
{
	va_list		 ap;

	va_start(ap, format);
	vsnprintf(h->errmsg, ERRSIZE, format, ap);
	va_end(ap);
}

static void
insert_scrambled_password(struct rad_packet *req, const char *secret)
{
/*
 * FIXME: this prevents us from resending the request to a different server
 */
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];
	int padded_len;
	int pos;

	padded_len = req->pass_len == 0 ? 16 : (req->pass_len+15) & ~0xf;

	memcpy(md5, &req->packet[POS_AUTH], LEN_AUTH);
	for (pos = 0;  pos < padded_len;  pos += 16) {
		int i;

		/* Calculate the new scrambler */
		MD5Init(&ctx);
		MD5Update(&ctx, secret, strlen(secret));
		MD5Update(&ctx, md5, 16);
		MD5Final(md5, &ctx);

		/*
		 * Mix in the current chunk of the password, and copy
		 * the result into the right place in the request.  Also
		 * modify the scrambler in place, since we will use this
		 * in calculating the scrambler for next time.
		 */
		for (i = 0;  i < 16;  i++)
			req->packet[req->pass_pos + pos + i] =
			    md5[i] ^= req->pass[pos + i];
	}
}

static void
insert_request_authenticator(struct rad_packet *req, const char *secret)
{
	MD5_CTX ctx;

	memset(&req->packet[POS_AUTH], 0, LEN_AUTH);

	/* Create the request authenticator */
	MD5Init(&ctx);
	MD5Update(&ctx, &req->packet, req->len);
	MD5Update(&ctx, secret, strlen(secret));
	MD5Final(&req->packet[POS_AUTH], &ctx);
}

static void
insert_response_authenticator(struct rad_packet *resp, const char *secret)
{
	MD5_CTX ctx;

	/* Create the response authenticator */
	MD5Init(&ctx);
	MD5Update(&ctx, &resp->packet, resp->len);
	MD5Update(&ctx, secret, strlen(secret));
	MD5Final(&resp->packet[POS_AUTH], &ctx);
}

static void
insert_message_authenticator(struct rad_packet *req, const char *secret)
{
#if defined(WITH_SSL) || defined(WITH_TOMCRYPT) || defined(HAVE_LIBPOLARSSL)
	u_char md[EVP_MAX_MD_SIZE];
	u_int md_len;
	HMAC_CTX ctx;

	if (req->authentic_pos != 0) {
		memset(&req->packet[req->authentic_pos + 2], 0, 16);
		HMAC_CTX_init(&ctx);
		HMAC_Init(&ctx, secret, strlen(secret), EVP_md5());
		/* FIXME: this and how this function is used is almost certainly wrong */
		HMAC_Update(&ctx, &req->packet, req->len);
		HMAC_Final(&ctx, md, &md_len);
		HMAC_CTX_cleanup(&ctx);
		HMAC_cleanup(&ctx);
		memcpy(&req->packet[req->authentic_pos + 2], md, MD5_DIGEST_LENGTH);
	}
#endif
}

/*
 * Return true if the current response is valid for a request to the
 * specified server.
 */
static int
is_valid_response(struct rad_handle *h, const char *secret)
{
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];
	int len;
	struct rad_packet *req = &h->request;
	struct rad_packet *resp = &h->response;
	struct rad_server_node *node = h->server;
	struct rad_server *server = node ? node->server : NULL;

	/* Check the message length */
	if (resp->len < POS_ATTRS) {
		if (server)
			server->stats.malformed_responses++;
		return 0;
	}
	len = resp->packet[POS_LENGTH] << 8 | resp->packet[POS_LENGTH+1];
	if (len > resp->len) {
		if (server)
			server->stats.malformed_responses++;
		return 0;
	}

	/* Check the response authenticator */
	MD5Init(&ctx);
	MD5Update(&ctx, &resp->packet[POS_CODE], POS_AUTH - POS_CODE);
	MD5Update(&ctx, &req->packet[POS_AUTH], LEN_AUTH);
	MD5Update(&ctx, &resp->packet[POS_ATTRS], len - POS_ATTRS);
	MD5Update(&ctx, secret, strlen(secret));
	MD5Final(md5, &ctx);
	if (memcmp(&resp->packet[POS_AUTH], md5, sizeof md5) != 0) {
		if (server)
			server->stats.bad_authenticators++;
		return 0;
	}

#if defined(WITH_SSL) || defined(WITH_TOMCRYPT) || defined(HAVE_LIBPOLARSSL)
	/*
	 * For non accounting responses check the message authenticator,
	 * if any.
	 */
	if (resp->packet[POS_CODE] != RAD_ACCOUNTING_RESPONSE) {
		HMAC_CTX hctx;
		u_char respb[resp->len], md[EVP_MAX_MD_SIZE];
		int pos, md_len;

		/*
		 * FIXME: copying the whole message is somewhat wastefull
		 */
		memcpy(respb, resp->packet, resp->len);
		pos = POS_ATTRS;

		/* Search and verify the Message-Authenticator */
		while (pos < len - 2) {

			if (resp->packet[pos] == RAD_MESSAGE_AUTHENTIC) {
				/* zero fill the Message-Authenticator */
				memset(&respb[pos + 2], 0, MD5_DIGEST_LENGTH);

				HMAC_CTX_init(&hctx);
				HMAC_Init(&hctx, secret, strlen(secret), EVP_md5());
				HMAC_Update(&hctx, &respb[POS_CODE], POS_AUTH - POS_CODE);
				HMAC_Update(&hctx, &req->packet[POS_AUTH], LEN_AUTH);
				HMAC_Update(&hctx, &respb[POS_ATTRS], resp->len - POS_ATTRS);
				HMAC_Final(&hctx, md, &md_len);
				HMAC_CTX_cleanup(&hctx);
				HMAC_cleanup(&hctx);
				if (memcmp(md, &resp->packet[pos + 2], MD5_DIGEST_LENGTH) != 0) {
					if (server)
						server->stats.bad_authenticators++;
					return 0;
				}
				break;
			}
			pos += resp->packet[pos + 1];
		}
	}
#endif
	return 1;
}

/*
 * Return true if the current response is valid for a request to the
 * specified server.
 */
int
is_valid_request(struct rad_packet *req, const char *secret)
{
	MD5_CTX ctx;
	unsigned char md5[MD5_DIGEST_LENGTH];
	int len;

	/* Check the message length */
	if (req->len < POS_ATTRS)
		return 0;
	len = req->packet[POS_LENGTH] << 8 | req->packet[POS_LENGTH+1];
	if (len > req->len)
		return 0;

	if (req->packet[POS_CODE] == RAD_ACCOUNTING_REQUEST) {
		/* Check the request authenticator */
		MD5Init(&ctx);
		MD5Update(&ctx, &req->packet[POS_CODE], POS_AUTH - POS_CODE);
		MD5Update(&ctx, memset(md5, 0, LEN_AUTH), LEN_AUTH);
		MD5Update(&ctx, &req->packet[POS_ATTRS], len - POS_ATTRS);
		MD5Update(&ctx, secret, strlen(secret));
		MD5Final(md5, &ctx);
		if (memcmp(&req->packet[POS_AUTH], md5, sizeof md5) != 0)
			return 0;
	}

#if defined(WITH_SSL) || defined(WITH_TOMCRYPT) || defined(HAVE_LIBPOLARSSL)
	/*
	 * For non accounting requests check the message authenticator,
	 * if any.
	 */
	if (req->packet[POS_CODE] == RAD_ACCESS_REQUEST) {
		HMAC_CTX hctx;
		u_char reqb[req->len], md[EVP_MAX_MD_SIZE];
		int pos, md_len;

		/*
		 * FIXME: copying the whole message is somewhat wastefull
		 */
		memcpy(reqb, req->packet, req->len);
		pos = POS_ATTRS;

		/* Search and verify the Message-Authenticator */
		while (pos < len - 2) {

			if (req->packet[pos] == RAD_MESSAGE_AUTHENTIC) {
				/* zero fill the Message-Authenticator */
				memset(&reqb[pos + 2], 0, MD5_DIGEST_LENGTH);

				HMAC_CTX_init(&hctx);
				HMAC_Init(&hctx, secret, strlen(secret), EVP_md5());
				HMAC_Update(&hctx, &req->packet[POS_CODE], POS_AUTH - POS_CODE);
				HMAC_Update(&hctx, &req->packet[POS_AUTH], LEN_AUTH);
				HMAC_Update(&hctx, &reqb[POS_CODE], req->len);
				HMAC_Final(&hctx, md, &md_len);
				HMAC_CTX_cleanup(&hctx);
				HMAC_cleanup(&hctx);
				if (memcmp(md, &req->packet[pos + 2],
				    MD5_DIGEST_LENGTH) != 0)
					return 0;
				break;
			}
			pos += req->packet[pos + 1];
		}
	}
#endif
	return 1;
}

static int
put_password_attr(struct rad_packet *req, int type, const void *value, size_t len)
{
	int padded_len;
	int pad_len;

	if (req->pass_pos != 0)
		return -1;

	if (len > PASSSIZE)
		len = PASSSIZE;
	padded_len = len == 0 ? 16 : (len+15) & ~0xf;
	pad_len = padded_len - len;

	/*
	 * Put in a place-holder attribute containing all zeros, and
	 * remember where it is so we can fill it in later.
	 */
	clear_password(req);
	put_raw_attr(req, type, req->pass, padded_len);
	req->pass_pos = req->len - padded_len;

	/* Save the cleartext password, padded as necessary */
	memcpy(req->pass, value, len);
	req->pass_len = len;
	memset(req->pass + len, 0, pad_len);

	return 0;
}

static int
put_raw_attr(struct rad_packet *req, int type, const void *value, size_t len)
{
	if (len > 253 || req->len + 2 + len > MSGSIZE)
		return -1;

	req->packet[req->len++] = type;
	req->packet[req->len++] = len + 2;
	memcpy(&req->packet[req->len], value, len);
	req->len += len;

	return 0;
}

void
rad_notify(int res, struct rad_handle *h)
{
	assert(h);

	struct rad_setup *s = h->setup;

	assert(s);

	if (s->cb)
		s->cb(res, h, s->user, h->data);

	rad_close(h);
}

/*
 * queue handling functions
 */

/*
 * remove a request with the give id from the queue
 */
static inline struct rad_handle *
rad_dequeue_req_only(struct rad_queue *q, int id)
{
	struct rad_handle *h = NULL;

	assert(q);
	assert(id >= 0);
	assert(id < 256);

	if (q->requests[id] != NULL) {
		h = q->requests[id];
		h->id = -1;
		h->queue = NULL;
		q->requests[id] = NULL;
		q->outstanding--;
		q->server->stats.pending_requests--;
	}

	return h;
}

/*
 * remove a request with the give id from the queue and close the queue is appropriate
 */
static struct rad_handle *
rad_dequeue_req(struct rad_queue *q, int id)
{
	struct rad_handle *h;

	assert(q);
	assert(id >= 0);
	assert(id < 256);

	h = rad_dequeue_req_only(q, id);

	if (q->outstanding == 0) {
		rad_queue_stop_timer(q);
		if (q->next_id > 255)
			rad_close_queue(q);
	}

	return h;
}

static void rad_queue_read(EV_P_ ev_io *w, int revents)
{
	struct rad_queue *q = EVCAST(struct rad_queue, event, w);

	if (!(revents & EV_READ)) 
		return;

	struct sockaddr_in from;
	int fromlen;
	
	unsigned char	 response[MSGSIZE];
	int		 resp_len;
	int              id;
	struct rad_handle *h;

	assert(w->fd == q->fd);
	
	fromlen = sizeof from;
	resp_len = recvfrom(w->fd, response,
			    MSGSIZE, MSG_WAITALL, (struct sockaddr *)&from, &fromlen);
	
	if (resp_len == -1)
		return;
	
	if (resp_len < MINMSGSIZE) {
		fprintf(stderr, "radius reply to short: %d\n", resp_len);
		return;
	}
	
	id = response[POS_IDENT];
	
	/* Check the source address */
	if (from.sin_family != q->server->addr.sin_family ||
	    from.sin_addr.s_addr != q->server->addr.sin_addr.s_addr ||
	    from.sin_port != q->server->addr.sin_port) {
		switch (q->server->type) {
		case RADIUS_AUTH:
			rad_auth_invalid_server_addresses++;
			break;
			
		case RADIUS_ACCT:
			rad_acct_invalid_server_addresses++;
			break;
		}
		
		return;
	}
	
	/* match with request */
	h = q->requests[id];
	if (!h) {
		q->server->stats.packets_dropped++;
		return;
	}
	
	memcpy(h->response.packet, response, resp_len);
	h->response.len = resp_len;
	
	if (is_valid_response(h, q->server->secret)) {
		rad_dequeue_req(q, id);
		
		h->response.len = h->response.packet[POS_LENGTH] << 8 |
			h->response.packet[POS_LENGTH+1];
		h->response.pos = POS_ATTRS;
		
		switch (h->response.packet[POS_CODE]) {
		case RAD_ACCESS_ACCEPT:
			h->server->server->stats.access_accepts++;
			break;
			
		case RAD_ACCESS_REJECT:
			h->server->server->stats.access_rejects++;
			break;
			
		case RAD_ACCESS_CHALLENGE:
			h->server->server->stats.access_challenges++;
			break;
			
		case RAD_ACCOUNTING_RESPONSE:
			h->server->server->stats.responses++;
			break;
			
		default:
			h->server->server->stats.unknown_types++;
			break;
		}
		rad_notify(h->response.packet[POS_CODE], h);
	}
}

/*
 * create a new queue
 */
static struct rad_queue *
rad_new_queue(struct rad_server *srv)
{
	struct rad_queue *q;

	q = (struct rad_queue *)malloc(sizeof(struct rad_queue));
	if (!q)
		return NULL;

	memset(q, 0, sizeof(struct rad_queue));

	/* Open a socket to use */
	struct sockaddr_in sin;
	
	if ((q->fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		free(q);
		return NULL;
	}
	memset(&sin, 0, sizeof sin);
	/*
	  sin.sin_len = sizeof sin;
	*/
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(0);
	if (bind(q->fd, (const struct sockaddr *)&sin,
		 sizeof sin) == -1) {
		close(q->fd);
		free(q);
		return NULL;
	}

	ev_timer_init(&q->timer, rad_queue_timeout, 0., 1.);

	ev_io_init(&q->event, rad_queue_read, q->fd, EV_READ);
	ev_io_start(EV_DEFAULT_ &q->event);

	q->server = srv;
	LIST_INSERT_HEAD(&srv->queues, q, next);

	return q;
}

static timestamp
get_ts(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return ((timestamp)tv.tv_sec) * 1000 + tv.tv_usec / 1000;
}

/*
 * Clean up a queue that is spent
 */
static void
rad_close_queue(struct rad_queue *q)
{
	assert(q);
	assert(q->outstanding == 0);

	ev_io_stop(EV_DEFAULT_ &q->event);
	ev_timer_stop(EV_DEFAULT_ &q->timer);

	if (q->fd != -1) {
		close(q->fd);
		q->fd = -1;
	}

	/* detach from server */
	LIST_REMOVE(q, next);

	free(q);
}

static void
rad_queue_start_timer(struct rad_queue *q)
{
	assert(q);

	if (!ev_is_active(&q->timer) &&
	    q->outstanding != 0)
		ev_timer_again(EV_DEFAULT_ &q->timer);
}

static void
rad_queue_stop_timer(struct rad_queue *q)
{
	assert(q);

	ev_timer_stop(EV_DEFAULT_ &q->timer);
}

static void
rad_queue_timeout(EV_P_ ev_timer *w, int revents __attribute__ ((unused)))
{
	struct rad_queue *q = EVCAST(struct rad_queue, timer, w);

	assert(q);

	if (q->outstanding == 0) {
		/*
		 * a queue with outstanding requests should not have a timer enabled
		 */
		rad_queue_stop_timer(q);
		if (q->next_id > 255)
			rad_close_queue(q);
		return;
	}

	/* TODO: this could be a bit more optimized
	 * - remember the 1st element
	 * - use a binary heap for the timeout values.....
	 */

	timestamp now = get_ts();

	for (int i = 0; i < q->next_id; i++) {
		if (q->requests[i] == NULL)
			continue;

		if (q->requests[i]->timeout < now) {
			struct rad_handle *h = q->requests[i];
			struct rad_setup *s = h->setup;
			struct rad_server_node *node = h->server;
			struct rad_server *srv = node->server;

			/*
			 * round robin scheduling for radius servers,
			 * a failed server is also moved to the end to the chain
			 */
			if (h->try >= srv->max_tries) {
				/*
				 * select a new server
				 */
				rad_dequeue_req_only(q, i);
				srv->stats.timeouts++;

				h->try = 0;

				node = TAILQ_NEXT(node, next);
				/* put_server_node() can only kill the current node, not the next one */
				put_server_node(&h->server);
				
				if (!node) {
					generr(h, "No valid RADIUS responses received");
					rad_notify(-1, h);
					continue;
				}
				h->server = get_server_node(node);
				if (node->server)
					node->server->stats.requests++;
			} else {
				if (node->server)
					node->server->stats.retransmissions++;
			}

			/* resend the request */
			if (rad_sendto_srv(h) != 0) {
				rad_detach_queue_only(h);
				rad_notify(-1, h);
				continue;
			}
		}
	}

	if (q->outstanding == 0) {
		rad_queue_stop_timer(q);
		if (q->next_id > 255)
			rad_close_queue(q);
	} else
		/* rearm timer */
		ev_timer_again (EV_A_ w);
}

/*
 * add a request with the to the queue
 */
static int
rad_enqueue_req(struct rad_queue *q, struct rad_handle *h)
{
	int r;

	assert(q);
	assert(h);

	r = q->next_id;
	q->requests[r] = h;
	h->queue = q;
	h->id = r;
	q->next_id++;
	q->outstanding++;
	q->server->stats.pending_requests++;

	rad_queue_start_timer(q);

	return r;
}

static void
rad_detach_queue_only(struct rad_handle *h)
{
	if (h->id >= 0 && h->id < 256 &&
	    h->queue &&
	    h->queue->requests[h->id] == h) {
		rad_dequeue_req_only(h->queue, h->id);
		h->queue = NULL;
	}
}

static void
rad_detach_queue(struct rad_handle *h)
{
	if (h->id >= 0 && h->id < 256 &&
	    h->queue &&
	    h->queue->requests[h->id] == h) {
		rad_dequeue_req(h->queue, h->id);
		h->queue = NULL;
	}
}

/*
 * release an rad_handle
 */
void
rad_close(struct rad_handle *h)
{
	if (h->queue)
		rad_detach_queue(h);
	if (h->server)
		put_server_node(&h->server);

	clear_password(&h->request);
	free(h);
}

static int
rad_sendto_srv(struct rad_handle *h)
{
	int n;
	int updated = 0;
	struct rad_queue *q;
	struct rad_server *srv;

	if (!h->server || !h->server->server) {
		generr(h, "No radius server");
		return -1;
	}
	srv = h->server->server;

	if (h->try != 0) {
		/* update Event-Timestamp and Acct-Delay-Time */
		time_t now = time(NULL);

		if (h->request.acct_delay_pos != 0) {
			*(time_t *)(&h->request.packet[h->request.acct_delay_pos + 2]) = htonl(now - h->request.request_created);
			updated = 1;
		}
	}

	q = h->queue;
	if (q && updated) {
		/*
		 * packet has changed, need to give it a new id as well
		 *
		 * ATTN: we could be called from rad_queue_timeout() which walkes the queue,
		 *       so don't destroy the queue, otherwise strange things will happen....
		 */
		rad_detach_queue_only(h);
		q = NULL;
	}

	if (!q) {
		if (LIST_EMPTY(&srv->queues) || LIST_FIRST(&srv->queues)->next_id > 255) {
			if (!rad_new_queue(srv)) {
				generr(h, "Out of memory");
				return -1;
			}
		}
		q = LIST_FIRST(&srv->queues);

		rad_enqueue_req(q, h);
		h->request.packet[POS_IDENT] = h->id;
		updated = 1;
	}

	if (updated) {
		if (h->request.packet[POS_CODE] == RAD_ACCOUNTING_REQUEST)
			/* Insert the request authenticator into the request */
			insert_request_authenticator(&h->request, srv->secret);
		else {
			/* Insert the scrambled password into the request */
			if (h->request.pass_pos != 0)
				insert_scrambled_password(&h->request, srv->secret);
			insert_message_authenticator(&h->request, srv->secret);
		}
	}

	h->try++;
	h->timeout = get_ts() + srv->timeout * 1000;

	/* Send the request */
	n = sendto(q->fd, h->request.packet, h->request.len, 0,
		   (const struct sockaddr *)&(srv->addr),
		   sizeof srv->addr);
	if (n != h->request.len) {
		if (n == -1)
			generr(h, "sendto: %s", strerror(errno));
		else
			generr(h, "sendto: short write");
		return -1;
	}

	return 0;
}

struct rad_packet *
rad_init_request(struct rad_handle *h, int code)
{
	struct rad_packet *req = &h->request;

	req->packet[POS_CODE] = code;

#if defined(WITH_TOMCRYPT)
	if (yarrow_ready(&(prng)) == CRYPT_OK)
		yarrow_read(&(req->packet[POS_AUTH]), LEN_AUTH, &(prng));
	else
#elif defined (HAVE_LIBPOLARSSL)
	if (42) {
		for (unsigned int i = 0; i < LEN_AUTH / sizeof(unsigned int); i++)
			((unsigned int *)&req->packet[POS_AUTH])[i] = havege_rand(&h_state);
	} else

#endif
	/* Create a random authenticator */
	for (int i = 0;  i < LEN_AUTH;  i += 2) {
		long r;
		r = random();
		req->packet[POS_AUTH+i] = (u_char)r;
		req->packet[POS_AUTH+i+1] = (u_char)(r >> 8);
	}
	req->len = POS_ATTRS;
	clear_password(req);
	req->request_created = time(NULL);
	return req;
}

struct rad_packet *
rad_new_request(const unsigned char *data, ssize_t len)
{
	struct rad_packet *req;

	if (len > MSGSIZE)
		return NULL;

	req = (struct rad_packet *)malloc(sizeof(struct rad_packet));
	if (req == NULL)
		return NULL;

	memset(req, 0, sizeof(struct rad_packet));
	memcpy(req->packet, data, len);
	req->len = len;
	req->pos = POS_ATTRS;
	clear_password(req);
	req->request_created = time(NULL);

	return req;
}

struct rad_packet *
rad_init_response(const struct rad_packet *req, int code)
{
	struct rad_packet *resp;

	resp = (struct rad_packet *)malloc(sizeof(struct rad_packet));
	if (resp == NULL)
		return NULL;

	memset(resp, 0, sizeof(struct rad_packet));
	resp->packet[POS_CODE] = code;
	resp->packet[POS_IDENT] = req->packet[POS_IDENT];
	memcpy(&resp->packet[POS_AUTH], &req->packet[POS_AUTH], LEN_AUTH);

	resp->len = POS_ATTRS;
	clear_password(resp);
	resp->request_created = 1;

	return resp;
}

void rad_free_packet(const struct rad_packet *req)
{
	free(req);
}

/*
 * sendto(...) wrapper for radius packets
 */
int
rad_send_answer(int s, struct rad_packet *resp, const char *secret,
		int flags, const struct sockaddr *to, socklen_t tolen)
{
	resp->packet[POS_LENGTH] = resp->len >> 8;
	resp->packet[POS_LENGTH+1] = resp->len & 0xff;

	if (resp->packet[POS_CODE] != RAD_ACCOUNTING_RESPONSE)
		insert_message_authenticator(resp, secret);
	insert_response_authenticator(resp, secret);

	return sendto(s, resp->packet, resp->len, flags, to, tolen);
}

int
rad_send_answer_from(int s, struct rad_packet *resp, const char *secret,
		     int flags, const struct sockaddr *to, socklen_t tolen,
		     const struct in_addr from)
{
	struct iovec iov = {
		.iov_base = resp->packet,
		.iov_len  = resp->len,
	};

	char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct in_pktinfo *pkt;
	struct cmsghdr *cmsg;

	struct msghdr msg = {
		.msg_name = to,
		.msg_namelen = tolen,

		.msg_iov = &iov,
		.msg_iovlen = 1,

		.msg_controllen = sizeof(cbuf),
		.msg_control    = &cbuf,
		.msg_flags = 0,
	};

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_PKTINFO;  
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

	pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
	pkt->ipi_ifindex = 0;
	pkt->ipi_spec_dst = from;
	pkt->ipi_addr = ((struct sockaddr_in *)to)->sin_addr;

	msg.msg_controllen = cmsg->cmsg_len;

	resp->packet[POS_LENGTH] = resp->len >> 8;
	resp->packet[POS_LENGTH+1] = resp->len & 0xff;

	if (resp->packet[POS_CODE] != RAD_ACCOUNTING_RESPONSE)
		insert_message_authenticator(resp, secret);
	insert_response_authenticator(resp, secret);

	return sendmsg(s, &msg, flags);
}

struct in_addr
rad_cvt_addr(const void *data)
{
	struct in_addr value;

	memcpy(&value.s_addr, data, sizeof value.s_addr);
	return value;
}

u_int32_t
rad_cvt_int(const void *data)
{
	u_int32_t value;

	memcpy(&value, data, sizeof value);
	return ntohl(value);
}

u_int64_t
rad_cvt_int64(const void *data)
{
	u_int64_t value;

	memcpy(&value, data, sizeof value);
	return ntohll(value);
}

char *
rad_cvt_string(const void *data, size_t len)
{
	char *s;

	s = malloc(len + 1);
	if (s != NULL) {
		memcpy(s, data, len);
		s[len] = '\0';
	}
	return s;
}

int rad_get_code(struct rad_packet *req)
{
	return req->packet[POS_CODE];
}

/*
 * reset the internal get pointer
 */
void rad_get_reset(struct rad_packet *req)
{
	req->pos = POS_ATTRS;
}

/*
 * Returns the attribute type.  If none are left, returns 0.  On failure,
 * returns -1.
 */
int
rad_get_attr(struct rad_packet *req, const void **value, size_t *len)
{
	int type;

	if (req->pos >= req->len)
		return 0;
	if (req->pos + 2 > req->len)
		return -1;

	type = req->packet[req->pos++];
	*len = req->packet[req->pos++] - 2;
	if (req->pos + (int)*len > req->len)
		return -1;

	*value = &req->packet[req->pos];
	req->pos += *len;
	return type;
}

/*
 * Returns -1 on error, 0 to indicate no event and >0 for success
 */
int
rad_send_request(struct rad_setup *s, struct rad_handle *h)
{
	struct rad_server_node *srv;
	int rc = -1;

	if (h->type == s->type) {
		/* send only if request and server type match */

		/* Fill in the length field in the message */
		h->request.packet[POS_LENGTH] = h->request.len >> 8;
		h->request.packet[POS_LENGTH+1] = h->request.len;
		h->setup = s;
		
		
		srv = TAILQ_FIRST(&s->servers);
		if (srv && srv->server) {
			h->server = get_server_node(srv);
			h->server->server->stats.requests++;
			
			rc = rad_sendto_srv(h);
		}
	}

	if (rc < 0)
		rad_notify(rc, h);

	return rc;
}

/*
 * Create and initialize a rad_setup structure, and return it to the
 * caller.  Can fail only if the necessary memory cannot be allocated.
 * In that case, it returns NULL.
 */
struct rad_setup *
rad_setup_open(int type, rad_notify_cb *cb, void *user)
{
	struct rad_setup *s;

	s = (struct rad_setup *)malloc(sizeof(struct rad_setup));
	if (s != NULL)
		memset(s, 0, sizeof(struct rad_setup));
	s->type = type;
	s->cb = cb;
	s->user = user;

	TAILQ_INIT(&s->servers);

	return s;
}

static void
rad_cleanup_server_queues(struct rad_server *srvp)
{
	struct rad_queue *cur;

	while ((cur = LIST_FIRST(&srvp->queues))) {
		for (int id = 0; id < cur->next_id; id++) {
			struct rad_handle *h = cur->requests[id];

			if (h) {
				/* prevent rad_notify from calling rad_detach_queue
				 * which may prematurely rad_close_queue 'cur'
				 */
				rad_detach_queue_only(h);
				rad_notify(-1, h);
			}
		}

		rad_close_queue(cur);
	}
}

int
rad_update_server(struct rad_server *srvp,
		  int type, const struct in_addr host, int port,
		  const char *secret, int timeout, int tries)
{
	if (!srvp)
		return -1;

	rad_cleanup_server_queues(srvp);

	srvp->type = type;
	srvp->addr.sin_family = AF_INET;
	srvp->addr.sin_addr = host;
	srvp->addr.sin_port = htons((u_short)port);

	free(srvp->secret);
	if ((srvp->secret = strdup(secret)) == NULL)
		return -1;

	srvp->timeout = timeout;
	srvp->max_tries = tries;

	memset(&srvp->stats, 0, sizeof(struct rad_stats));

	return 0;
}

struct rad_server *
rad_new_server(int type, const struct in_addr host, int port,
	       const char *secret, int timeout, int tries)
{
	struct rad_server *srvp;

	srvp = (struct rad_server *)malloc(sizeof(struct rad_server));
	if (!srvp)
		return NULL;

	memset(srvp, 0, sizeof(struct rad_server));

	if (rad_update_server(srvp, type, host, port, secret, timeout, tries) == -1) {
		free(srvp);
		return NULL;
	}

	return srvp;
}

void
rad_free_server(struct rad_server *srvp)
{
	if (!srvp)
		return;

	rad_cleanup_server_queues(srvp);
	free(srvp);
}

int
rad_add_server(struct rad_setup *s, uint32_t id, struct rad_server *srvp)
{
	struct rad_server_node *n;
	struct rad_server_node *node;

	if (!s || !srvp)
		return -1;

	if (s->type != srvp->type)
		return -1;

	n = (struct rad_server_node *)malloc(sizeof(struct rad_server_node));
	if (!n)
		return -1;

	n->id = id;
	n->server = srvp;
	n->ref_cnt = 1;

	TAILQ_FOREACH(node, &s->servers, next) {
		if (node->id > id) {
			if (node == TAILQ_FIRST(&s->servers))
				TAILQ_INSERT_HEAD(&s->servers, n, next);
			else
				TAILQ_INSERT_BEFORE(node, n, next);

			return 0;
		}
	}

	TAILQ_INSERT_TAIL(&s->servers, n, next);
		
	return 0;
}

int
rad_remove_server(struct rad_setup *s, uint32_t id)
{
	struct rad_server_node *node;

	if (!s)
		return -1;

	TAILQ_FOREACH(node, &s->servers, next) {
		if (node->id == id) {
			TAILQ_REMOVE(&s->servers, node, next);
			memset(&node->next, 0, sizeof(node->next));
			put_server_node(&node);

			return 0;
		}
	}

	return -1;
}

/*
 * Create and initialize a rad_handle structure, and return it to the
 * caller.  Can fail only if the necessary memory cannot be allocated.
 * In that case, it returns NULL.
 */
struct rad_handle *
rad_auth_open(void *data)
{
	struct rad_handle *h;

	h = (struct rad_handle *)malloc(sizeof(struct rad_handle));
	if (h != NULL) {
		memset(h, 0, sizeof(struct rad_handle));
		h->data = data;
		h->type = RADIUS_AUTH;
	}
	return h;
}

struct rad_handle *
rad_acct_open(void *data)
{
	struct rad_handle *h;

	h = rad_auth_open(data);
	if (h != NULL)
	        h->type = RADIUS_ACCT;
	return h;
}

int
rad_put_addr(struct rad_packet *req, int type, struct in_addr addr)
{
	return rad_put_attr(req, type, &addr.s_addr, sizeof addr.s_addr);
}

static int
rad_put_acct_delay_time(struct rad_packet *req, int type, const void *value, size_t len)
{
	req->acct_delay_pos = req->len;
	return put_raw_attr(req, type, value, len);
}

int
rad_put_attr(struct rad_packet *req, int type, const void *value, size_t len)
{
	int result;

	if (!req->request_created)
		return -1;

	/*
	 * When proxying EAP Messages, the Message Authenticator
	 * MUST be present; see RFC 3579.
	 */
	if (type == RAD_EAP_MESSAGE) {
		if (rad_put_message_authentic(req) == -1)
			return -1;
	}

	if (type == RAD_USER_PASSWORD) {
		result = put_password_attr(req, type, value, len);
	} else if (type == RAD_MESSAGE_AUTHENTIC) {
		result = rad_put_message_authentic(req);
	} else if (type == RAD_ACCT_DELAY_TIME) {
		result = rad_put_acct_delay_time(req, type, value, len);
	} else {
		result = put_raw_attr(req, type, value, len);
	}

	return result;
}

int
rad_put_int(struct rad_packet *req, int type, u_int32_t value)
{
	u_int32_t nvalue;

	nvalue = htonl(value);
	return rad_put_attr(req, type, &nvalue, sizeof nvalue);
}

int
rad_put_int64(struct rad_packet *req, int type, u_int64_t value)
{
	u_int64_t nvalue;

	nvalue = htonll(value);
	return rad_put_attr(req, type, &nvalue, sizeof nvalue);
}

int
rad_put_string(struct rad_packet *req, int type, const char *str)
{
	return rad_put_attr(req, type, str, strlen(str));
}

int
rad_put_message_authentic(struct rad_packet *req)
{
#if defined(WITH_SSL) || defined(WITH_TOMCRYPT) || defined(HAVE_LIBPOLARSSL)
	u_char md_zero[MD5_DIGEST_LENGTH];

	if (req->packet[POS_CODE] == RAD_ACCOUNTING_REQUEST)
		return -1;

	if (req->authentic_pos == 0) {
		req->authentic_pos = req->len;
		memset(md_zero, 0, sizeof(md_zero));
		return (put_raw_attr(req, RAD_MESSAGE_AUTHENTIC, md_zero,
		    sizeof(md_zero)));
	}
	return 0;
#else
	return -1;
#endif
}

const char *
rad_strerror(struct rad_handle *h)
{
	return h->errmsg;
}

int
rad_get_vendor_attr(u_int32_t *vendor, const void **data, size_t *len)
{
	struct vendor_attribute *attr;

	attr = (struct vendor_attribute *)*data;
	*vendor = ntohl(attr->vendor_value);
	*data = attr->attrib_data;
	*len = attr->attrib_len - 2;

	return (attr->attrib_type);
}

int
rad_put_vendor_addr(struct rad_packet *req, int vendor, int type,
    struct in_addr addr)
{
	return (rad_put_vendor_attr(req, vendor, type, &addr.s_addr,
	    sizeof addr.s_addr));
}

int
rad_put_vendor_attr(struct rad_packet *req, int vendor, int type,
    const void *value, size_t len)
{
	if (!req->request_created)
		return -1;

	if (len > 251 || req->len + 8 + len > MSGSIZE)
		return -1;

	req->packet[req->len++] = RAD_VENDOR_SPECIFIC;
	req->packet[req->len++] = len + 8;
	req->packet[req->len++] = (vendor >> 24) & 0x00ff;
	req->packet[req->len++] = (vendor >> 16) & 0x00ff;
	req->packet[req->len++] = (vendor >>  8) & 0x00ff;
	req->packet[req->len++] = vendor         & 0x00ff;
	req->packet[req->len++] = type;
	req->packet[req->len++] = len + 2;
	memcpy(&req->packet[req->len], value, len);
	req->len += len;

	return 0;
}

int
rad_put_vendor_int(struct rad_packet *req, int vendor, int type, u_int32_t i)
{
	u_int32_t value;

	value = htonl(i);
	return (rad_put_vendor_attr(req, vendor, type, &value, sizeof value));
}

int
rad_put_vendor_string(struct rad_packet *req, int vendor, int type,
    const char *str)
{
	return (rad_put_vendor_attr(req, vendor, type, str, strlen(str)));
}

ssize_t
rad_request_authenticator(struct rad_packet *req, char *buf, size_t len)
{
	if (len < LEN_AUTH)
		return (-1);
	memcpy(buf, req->packet + POS_AUTH, LEN_AUTH);
	if (len > LEN_AUTH)
		buf[LEN_AUTH] = '\0';
	return (LEN_AUTH);
}

struct rad_packet *
rad_request(struct rad_handle *h)
{
	return &h->request;
}

struct rad_packet *
rad_response(struct rad_handle *h)
{
	return &h->response;
}

#if 0
/* FIXME: disabled for now */

u_char *
rad_demangle(struct rad_handle *h, const void *mangled, size_t mlen)
{
	char R[LEN_AUTH];
	const char *S;
	int i, Ppos;
	MD5_CTX Context;
	u_char b[MD5_DIGEST_LENGTH], *C, *demangled;

	if ((mlen % 16 != 0) || mlen > 128) {
		generr(h, "Cannot interpret mangled data of length %lu",
		    (u_long)mlen);
		return NULL;
	}

	C = (u_char *)mangled;

	/* We need the shared secret as Salt */
	S = rad_server_secret(h);
	if (!S) {
		generr(h, "Cannot obtain the RADIUS shared secret");
		return NULL;
	}

	/* We need the request authenticator */
	if (rad_request_authenticator(h, R, sizeof R) != LEN_AUTH) {
		generr(h, "Cannot obtain the RADIUS request authenticator");
		return NULL;
	}

	demangled = malloc(mlen);
	if (!demangled)
		return NULL;

	MD5Init(&Context);
	MD5Update(&Context, S, strlen(S));
	MD5Update(&Context, R, LEN_AUTH);
	MD5Final(b, &Context);
	Ppos = 0;
	while (mlen) {

		mlen -= 16;
		for (i = 0; i < 16; i++)
			demangled[Ppos++] = C[i] ^ b[i];

		if (mlen) {
			MD5Init(&Context);
			MD5Update(&Context, S, strlen(S));
			MD5Update(&Context, C, 16);
			MD5Final(b, &Context);
		}

		C += 16;
	}

	return demangled;
}

u_char *
rad_demangle_mppe_key(struct rad_handle *h, const void *mangled,
    size_t mlen, size_t *len)
{
	char R[LEN_AUTH];    /* variable names as per rfc2548 */
	const char *S;
	u_char b[MD5_DIGEST_LENGTH], *demangled;
	const u_char *A, *C;
	MD5_CTX Context;
	int Slen, i, Clen, Ppos;
	u_char *P;

	if (mlen % 16 != SALT_LEN) {
		generr(h, "Cannot interpret mangled data of length %lu",
		    (u_long)mlen);
		return NULL;
	}

	/* We need the RADIUS Request-Authenticator */
	if (rad_request_authenticator(h, R, sizeof R) != LEN_AUTH) {
		generr(h, "Cannot obtain the RADIUS request authenticator");
		return NULL;
	}

	A = (const u_char *)mangled;      /* Salt comes first */
	C = (const u_char *)mangled + SALT_LEN;  /* Then the ciphertext */
	Clen = mlen - SALT_LEN;
	S = rad_server_secret(h);    /* We need the RADIUS secret */
	if (!S) {
		generr(h, "Cannot obtain the RADIUS shared secret");
		return NULL;
	}

	Slen = strlen(S);
	P = alloca(Clen);        /* We derive our plaintext */

	MD5Init(&Context);
	MD5Update(&Context, S, Slen);
	MD5Update(&Context, R, LEN_AUTH);
	MD5Update(&Context, A, SALT_LEN);
	MD5Final(b, &Context);
	Ppos = 0;

	while (Clen) {
		Clen -= 16;

		for (i = 0; i < 16; i++)
		    P[Ppos++] = C[i] ^ b[i];

		if (Clen) {
			MD5Init(&Context);
			MD5Update(&Context, S, Slen);
			MD5Update(&Context, C, 16);
			MD5Final(b, &Context);
		}

		C += 16;
	}

	/*
	* The resulting plain text consists of a one-byte length, the text and
	* maybe some padding.
	*/
	*len = *P;
	if (*len > mlen - 1) {
		generr(h, "Mangled data seems to be garbage %zu %zu",
		    *len, mlen-1);
		return NULL;
	}

	if (*len > MPPE_KEY_LEN * 2) {
		generr(h, "Key to long (%zu) for me max. %d",
		    *len, MPPE_KEY_LEN * 2);
		return NULL;
	}
	demangled = malloc(*len);
	if (!demangled)
		return NULL;

	memcpy(demangled, P + 1, *len);
	return demangled;
}
#endif

const char *
rad_server_secret(struct rad_handle *h)
{
	if (h->server)
		return (h->server->server->secret);
	else
		return NULL;
}

void
rad_init(void)
{
	rad_auth_invalid_server_addresses = 0;
	rad_acct_invalid_server_addresses = 0;

	/* setup the PRNG */
#if defined(WITH_TOMCRYPT)
	register_prng(&yarrow_desc);
	if (rng_make_prng(128, find_prng("yarrow"), &(prng), NULL) == CRYPT_OK) {
		yarrow_read((unsigned char *)&(ident), sizeof(ident), &(prng));
	} else
#endif
	{
		srandomdev();
		ident = random();
	}
}
