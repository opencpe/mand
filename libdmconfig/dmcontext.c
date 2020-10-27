/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * dmconfig library
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <ev.h>
#include <syslog.h>
#include <signal.h>
#include <sys/queue.h>

#include "debug.h"

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "dmmsg.h"
#include "codes.h"
#include "dmcontext.h"
#include "dmconfig.h"

#include "utils/logx.h"
#include "utils/binary.h"

/* support multiple event loops? */
#if EV_MULTIPLICITY
#define EV_P_UNUSED_ EV_P __attribute__((unused)),
#define SOCK_EV_(sock) (sock)->ev,
#else
#define EV_P_UNUSED_
#define SOCK_EV_(sock)
#endif

static void connectEvent(EV_P_ ev_io *w, int revents);
static void acceptEvent(EV_P_ ev_io *w, int revents);
static void writeEvent(EV_P_UNUSED_ ev_io *w, int revents);
static void readEvent(EV_P_UNUSED_ ev_io *w, int revents);

/* callbacks used by the blocking API automatically */

/* socket helper */
static void dm_stop_events(DMCONTEXT *sock);
static void dm_free_requests(DMCONTEXT *sock, DMCONFIG_EVENT event);

/* process functions */
static void process_request(DMCONTEXT *socket, DM_PACKET *pkt);
static void process_reply(DMCONTEXT *socket, DM_PACKET *pkt);

/* global variables */

static uint32_t hopid = 0;
static uint32_t endid = 0;

#define CALLBACK(WHAT, ...)				\
	do {						\
		if (WHAT)				\
			(WHAT)(__VA_ARGS__);		\
	} while (0)

#define CALLBACK_RC(WHAT, ...)				\
	({						\
		uint32_t _rc = RC_OK;			\
		if (WHAT)				\
			_rc = (WHAT)(__VA_ARGS__);	\
		_rc;					\
	})
/** @private */
static void
connection_error(DMCONTEXT *socket, DMCONFIG_EVENT event)
{
	CALLBACK_RC(socket->connection_cb, event, socket, socket->userdata);
	dm_context_shutdown(socket, event);
}

/** allocate and initialize a new socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev event_base to use for this context
 *
 * @ingroup API
 */
DMCONTEXT*
dm_context_new()
{
	return talloc(NULL, DMCONTEXT);
}

/** aquire a reference to a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 *
 * @ingroup API
 */
void
dm_context_reference(DMCONTEXT *dmCtx)
{
	dmCtx->_ref++;
}

/** release a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 *
 * @ingroup API
 */
int
dm_context_release(DMCONTEXT *dmCtx)
{
	int r;

	dmCtx->_ref--;
	r = dmCtx->_ref;

	if (dmCtx->_ref == 0)
		talloc_free(dmCtx);

	return r;
}

/** shut down the socket in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 *
 * @ingroup API
 */
void
dm_context_shutdown(DMCONTEXT *sock, DMCONFIG_EVENT event)
{
	dm_stop_events(sock);
	dm_free_requests(sock, event);

	shutdown(sock->socket, SHUT_RDWR);
	close(sock->socket);
	sock->socket = -1;
}


/** @private  put a packet into the send queue
 */
uint32_t dm_enqueue(DMCONTEXT *socket, DM2_REQUEST *req, int flags, DMRESULT_CB cb, void *data)
{
	DM2_REQUEST_INFO *rqi;

	if (socket->socket < 0)
		return RC_ERR_CONNECTION;

	/* workaround: when the consumer is not keeping the event loop alive,
	 * i.e. using another event loop and calling only the synced methods,
	 */
	ev_now_update(socket->ev);

	if ((flags | REPLY) != REPLY) {
		/* initialize static hopid */
		switch (hopid) {		/* one never knows... */
		case 0:		srand((unsigned int)time(NULL));
				/* fallthrough */
		case MAX_INT:	hopid = endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
			break;
		default:	hopid = ++endid;
		}

		req->packet->hop2hop_id = htonl(hopid);
		req->packet->end2end_id = htonl(endid);
	}

	if (!(rqi = talloc_zero(socket, DM2_REQUEST_INFO)))
		return RC_ERR_ALLOC;
	rqi->packet = talloc_steal(rqi, req->packet);
	rqi->flags = flags;
	rqi->reply_cb = cb;
	rqi->userdata = data;
	rqi->status = REQUEST_SHALL_WRITE;
	rqi->code = dm_packet_code(req->packet);
	rqi->hopid = dm_hop2hop_id(req->packet);
	TAILQ_INSERT_TAIL(&socket->head, rqi, entries);

	trace(":[%p] ev active on writeCtx.io_ev %d", socket, ev_is_active(&socket->writeCtx.io_ev));
	if (!ev_is_active(&socket->writeCtx.io_ev)) {
		trace(":[%p] starting writeCtx.io_ev on %d", socket, socket->socket);
		ev_io_start(socket->ev, &socket->writeCtx.io_ev);

		socket->writeCtx.timer_ev.repeat = TIMEOUT_WRITE_REQUESTS;
		trace(":[%p] start event writeCtx.timer_ev %p ", socket, &socket->writeCtx.timer_ev);
		ev_timer_again(socket->ev, &socket->writeCtx.timer_ev);
	}

	return RC_OK;
}

/** @private */
static void
start_socket_events(DMCONTEXT *sock)
{
	trace(":[%p]", sock);
	ev_io_start(sock->ev, &sock->readCtx.io_ev);
}

/** @private libev timeout event handler,
 */
static void
connectTimeoutEvent(EV_P_UNUSED_ ev_timer *w, int revents __attribute__((unused)))
{
	DMCONTEXT *sock = w->data;

	trace(":[%p] on %d, 0x%04x", sock, sock->socket, revents);

	connection_error(sock, DMCONFIG_ERROR_CONNECT_TIMEOUT);
}

static void
readTimeoutEvent(EV_P_UNUSED_ ev_timer *w, int revents __attribute__((unused)))
{
	DMCONTEXT *sock = w->data;

	trace(":[%p] on %d, 0x%04x", sock, sock->socket, revents);

	connection_error(sock, DMCONFIG_ERROR_READ_TIMEOUT);
}

static void
writeTimeoutEvent(EV_P_UNUSED_ ev_timer *w, int revents __attribute__((unused)))
{
	DMCONTEXT *sock = w->data;

	trace(":[%p] on %d, 0x%04x", sock, sock->socket, revents);

	connection_error(sock, DMCONFIG_ERROR_WRITE_TIMEOUT);
}

/** @private default connect event handler,
 *           translate from libev to connect callback
 */
static void
connectEvent(EV_P_ ev_io *w, int revents)
{
	DMCONTEXT *sock = w->data;
	int rc;
	socklen_t size = sizeof(rc);

	trace(":[%p] on %d, 0x%04x", sock, w->fd, revents);

	ev_timer_stop(EV_A_ &sock->timer_socket_ev);
	ev_io_stop(EV_A_ w);

	if (w->fd != -1
	    && (!(revents & EV_WRITE)
		|| getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &rc, &size)
		|| size != sizeof(rc) || rc))
	{
	    	CALLBACK_RC(sock->connection_cb, DMCONFIG_ERROR_CONNECTING, sock, sock->userdata);
		return;
	}

	start_socket_events(sock);

	if (CALLBACK_RC(sock->connection_cb, DMCONFIG_CONNECTED, sock, sock->userdata) != RC_OK) {
		connection_error(sock, DMCONFIG_ERROR_CONNECTING);
		return;
	}
}

/** @private default connect event handler,
 *           translate from libev to connect callback
 */
static void
acceptEvent(EV_P_UNUSED_ ev_io *w, int revents)
{
	DMCONTEXT *acceptSock = w->data;
	DMCONTEXT *sock;
	int rc;
	socklen_t size = sizeof(rc);

	trace(":[%p] on %d, 0x%04x", acceptSock, w->fd, revents);

	if (w->fd != -1 &&
	    (!(revents & EV_READ) || getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &rc, &size) || size != sizeof(rc) || rc)) {
	    	CALLBACK_RC(acceptSock->connection_cb, DMCONFIG_ERROR_ACCEPTING, acceptSock, acceptSock->userdata);
		return;
	}

	if (!(sock = talloc_zero(NULL, DMCONTEXT)))
		return;

	trace(":[%p] new socket [%p]", acceptSock, sock);
	if (dm_accept(acceptSock, sock) != RC_OK) {
	    	CALLBACK_RC(acceptSock->connection_cb, DMCONFIG_ERROR_ACCEPTING, acceptSock, acceptSock->userdata);
		return;
	}

	start_socket_events(sock);

	if (CALLBACK_RC(sock->connection_cb, DMCONFIG_ACCEPTED, sock, sock->userdata) != RC_OK) {
		connection_error(sock, DMCONFIG_ERROR_ACCEPTING);
		return;
	}
}

/** @private libev read event handler,
 */
static void
readEvent(EV_P_ ev_io *w, int revents __attribute__((unused)))
{
	DMCONTEXT *socket = w->data;
	DM2_IOCONTEXT *ctx = &socket->readCtx;
	DM_PACKET buf;
	ssize_t len;

	trace(":[%p] on %d, 0x%04x", socket, w->fd, revents);

	ctx->timer_ev.repeat = TIMEOUT_CHUNKS;
	trace(":[%p] start event readCtx.timer_ev %p ", socket, &ctx->timer_ev);
	ev_timer_again(EV_A_ &ctx->timer_ev);

	trace(":[%p] ctx->left: %zd", socket, ctx->left);

 again:
	if (!ctx->left) {
		while ((len = recv(w->fd, &buf, sizeof(buf), MSG_PEEK)) == -1) {
			trace(":[%p] recv result %d (%m), len %zd", socket, errno, len);
			switch (errno) {
			case EWOULDBLOCK:
				return; // not data
			case EINTR:
				continue;
			case ETIMEDOUT:
			case ECONNRESET:
				connection_error(socket, DMCONFIG_ERROR_READING);
				return;
			default:
				connection_error(socket, DMCONFIG_ERROR_READING);
				return;
			}
		}

		trace(":[%p] recv loop exit %d (%m), len %zd", socket, errno, len);
		if (len == 0) {
			connection_error(socket, DMCONFIG_ERROR_READING);
			return;
		}
		trace(":[%p] recv %zd bytes", socket, len);
		hexdump((void *)&buf, len);

		if (len != sizeof(buf))
			return;

		ctx->pos = ctx->packet = talloc_size(socket, dm_packet_length(&buf));
		ctx->left = dm_packet_length(&buf);
		trace(":[%p] recv ctx->left: %zd", socket, ctx->left);
	}

	while (ctx->left > 0) {
		if ((len = read(w->fd, ctx->pos, ctx->left)) < 0) {
			trace(":[%p] read result %d (%m), len %zd", socket, errno, len);
			switch (errno) {
			case EWOULDBLOCK:
				ctx->timer_ev.repeat = TIMEOUT_CHUNKS;
				trace(":[%p] start event readCtx.timer_ev %p ", socket, &ctx->timer_ev);
				ev_timer_again(EV_A_ &ctx->timer_ev);
				return; // not data
			case EINTR:
				continue;
			case ETIMEDOUT:
			case ECONNRESET:
				connection_error(socket, DMCONFIG_ERROR_READING);
				return;
			default:
				connection_error(socket, DMCONFIG_ERROR_READING);
				return;
			}
		}
		trace(":[%p] read loop result %d (%m), len %zd", socket, errno, len);
		if (len == 0) {
			connection_error(socket, DMCONFIG_ERROR_READING);
			return;
		}

		trace(":[%p] read %zd bytes", socket, len);
		hexdump(ctx->pos, len);

		ctx->pos += len;
		ctx->left -= len;
	};

	if (ctx->left == 0) {
		trace(":[%p] stop event readCtx.timer_ev %p ", socket, &ctx->timer_ev);
		ev_timer_stop(EV_A_ &ctx->timer_ev);

#ifdef LIBDMCONFIG_DEBUG
		if (dmconfig_debug_level) {
			trace(":[%p] Recieved %s:", socket, dm_packet_flags(ctx->packet) & CMD_FLAG_REQUEST ? "request" : "reply");
			dump_dm_packet(ctx->packet);
		}
#endif
		dm_context_reference(socket);
		if (dm_packet_flags(ctx->packet) & CMD_FLAG_REQUEST)
			process_request(socket, ctx->packet);
		else
			process_reply(socket, ctx->packet);

		talloc_free(ctx->packet);
		ctx->packet = ctx->pos = NULL;
		ctx->left = 0;

		if (dm_context_release(socket) == 0)
			return;

		/* beware the loop!! */
		goto again;
	}

	return;
}

static void
process_request(DMCONTEXT *socket, DM_PACKET *pkt)
{
	DM2_AVPGRP grp;

	dm_init_packet(pkt, &grp);

	CALLBACK(socket->request_cb, socket, pkt, &grp, socket->userdata);
}

static void
process_reply(DMCONTEXT *socket, DM_PACKET *pkt)
{
	DM2_AVPGRP grp;
	DM2_REQUEST_INFO *req;

	dm_init_packet(pkt, &grp);

	if (TAILQ_EMPTY(&socket->head))
		return;

	TAILQ_FOREACH(req, &socket->head, entries)
		if (req->hopid == dm_hop2hop_id(pkt))
			break;

	if (!req || req->status != REQUEST_SHALL_READ)
		return;

	TAILQ_REMOVE(&socket->head, req, entries);
	talloc_steal(pkt, req);

	CALLBACK(req->reply_cb, socket, DMCONFIG_ANSWER_READY, &grp, req->userdata);
}

/** @private libev write event handler,
 */
static void
writeEvent(EV_P_ ev_io *w, int revents __attribute__((unused)))
{
	DMCONTEXT *socket = w->data;
	DM2_IOCONTEXT *ctx = &socket->writeCtx;
	DM2_REQUEST_INFO *req;
	ssize_t len;

	trace(":[%p] on %d, 0x%04x", socket, w->fd, revents);

	if (TAILQ_EMPTY(&socket->head))
		return;

	do {
		trace(":[%p] ctx->packet: %p", socket, ctx->packet);
		if (!ctx->packet) {
			TAILQ_FOREACH(req, &socket->head, entries) {
				if (req->status == REQUEST_SHALL_WRITE)
					break;
			}

			trace(":[%p] req: %p", socket, req);
			if (!req)
				/* all requests written */
				break;

			ctx->pos = ctx->packet = req->packet;
			ctx->left = dm_packet_length(ctx->packet);
			talloc_steal(socket, req->packet);

			if (req->flags & (ONE_WAY | REPLY)) {
				/* drop the packet from the request queue */
				TAILQ_REMOVE(&socket->head, req, entries);
				talloc_free(req);
			} else
				req->status = REQUEST_SHALL_READ;
		}

		trace(":[%p] ctx->left: %zd", socket, ctx->left);
		trace(":[%p] w->fd: %d, %d", socket, w->fd, socket->socket);

		while (ctx->left != 0) {
			if ((len = write(w->fd, ctx->pos, ctx->left)) < 0)
				switch (errno) {
				case EAGAIN:
					trace(":[%p] write errno #1: %m", socket);
					ctx->timer_ev.repeat = TIMEOUT_CHUNKS;
					trace(":[%p] start event writeCtx.timer_ev %p ", socket, &ctx->timer_ev);
					ev_timer_again(EV_A_ &ctx->timer_ev);
					return;
				case EPIPE:
				case ECONNRESET:
					trace(":[%p] write errno #2: %m", socket);
					connection_error(socket, DMCONFIG_ERROR_WRITING);
					return;
				case EINTR:
					trace(":[%p] write errno #3: %m", socket);
					continue;
				default:
					trace(":[%p] write errno #4: %m", socket);
					connection_error(socket, DMCONFIG_ERROR_WRITING);
					return;
				}

			trace(":[%p] wrote %zd bytes", socket, len);
			hexdump(ctx->pos, len);

			ctx->left -= len;
			ctx->pos += len;
		}
		trace(":[%p] loop exit: %zd bytes,ctx->left: %zd ", socket, len, ctx->left);

		if (ctx->left == 0) {
			talloc_free(ctx->packet);
			ctx->packet = NULL;
		}

	} while (!TAILQ_EMPTY(&socket->head));

	/* all requests written */
	ev_io_stop(EV_A_ &ctx->io_ev);

	trace(":[%p] stop event writeCtx.timer_ev %p ", socket, &ctx->timer_ev);
	ev_timer_stop(EV_A_ &ctx->timer_ev);
}

/** @private free all requests in a DMCONTEXT */
static void
dm_free_requests(DMCONTEXT *sock, DMCONFIG_EVENT event)
{
	while (!TAILQ_EMPTY(&sock->head)) {
		REQUESTINFO *r;

		r = TAILQ_FIRST(&sock->head);
		TAILQ_REMOVE(&sock->head, r, entries);
		CALLBACK(r->reply_cb, sock, event, NULL, r->userdata);
		talloc_free(r);
	}

	talloc_free(sock->writeCtx.packet);
	sock->writeCtx.packet = NULL;

	talloc_free(sock->readCtx.packet);
	sock->readCtx.packet = NULL;
}

/** @private free all events in a DMCONTEXT */
static void
dm_stop_events(DMCONTEXT *sock)
{
	trace(":[%p]", sock);

	ev_io_stop(SOCK_EV_(sock) &sock->writeCtx.io_ev);
	ev_timer_stop(SOCK_EV_(sock) &sock->writeCtx.timer_ev);

	ev_io_stop(SOCK_EV_(sock) &sock->readCtx.io_ev);
	ev_timer_stop(SOCK_EV_(sock) &sock->readCtx.timer_ev);

	ev_io_stop(SOCK_EV_(sock) &sock->io_socket_ev);
	ev_timer_stop(SOCK_EV_(sock) &sock->timer_socket_ev);
}

/** initialize a new socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev event_base to use for this context
 *
 * @ingroup API
 */
void
dm_context_init(DMCONTEXT *sock, struct ev_loop *base, int type,
		void *userdata, DMCONFIG_CONNECTION_CB connection_cb, DMCONFIG_CB request_cb)
{
	memset(sock, 0, sizeof(DMCONTEXT));
	sock->_ref = 1;
	TAILQ_INIT(&sock->head);
	sock->socket = -1;
	sock->ev = base;
	sock->type = type;
	sock->userdata = userdata;
	sock->connection_cb = connection_cb;
	sock->request_cb = request_cb;
}

static void
dm_init_events(DMCONTEXT *socket)
{
	ev_io_init(&socket->readCtx.io_ev, readEvent, socket->socket, EV_READ);
	socket->readCtx.io_ev.data = socket;
	ev_io_init(&socket->writeCtx.io_ev, writeEvent, socket->socket, EV_WRITE);
	socket->writeCtx.io_ev.data = socket;

	ev_timer_init(&socket->readCtx.timer_ev, readTimeoutEvent, 0., 0.);
	socket->readCtx.timer_ev.data = socket;
	ev_timer_init(&socket->writeCtx.timer_ev, writeTimeoutEvent, 0., 0.);
	socket->writeCtx.timer_ev.data = socket;

	ev_now_update(socket->ev);	/* workaround for libev time update problem
					   otherwise ev_now() time is updated only at ev_loop */
}

/** create a socket in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_CONNECTION    Underlying socket was closed or blocking
 */
static inline uint32_t
dm_create_socket(DMCONTEXT *sock)
{
	int fd = socket(sock->type == AF_UNIX ? PF_UNIX : PF_INET, SOCK_STREAM, 0);

	if (fd == -1)
		return RC_ERR_CONNECTION;

	sock->socket = fd;

	dm_init_events(sock);
	return RC_OK;
}


/** start an asynchonous connect
 *
 * Start an asynchonous connect and invoke a callback when the operation
 * completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] type        Type of socket (AF_INET or AF_UNIX)
 * @param [in] callback    Callback function to invoke
 * @param [in] userdata    Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_CONNECTION    Underlying socket was closed or blocking
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_connect_async(DMCONTEXT *sock)
{
	uint32_t rc;
	union {
		struct sockaddr_un sockaddr_un;
		struct sockaddr_in sockaddr_in;
	} sockaddr;

	socklen_t sockaddr_len;

	if (sock->socket <= 0)
		if ((rc = dm_create_socket(sock)) != RC_OK)
			return rc;

	fcntl(sock->socket, F_SETFL, fcntl(sock->socket, F_GETFL) | O_NONBLOCK);

	memset(&sockaddr, 0, sizeof(sockaddr));
	if (sock->type == AF_UNIX) {
		sockaddr.sockaddr_un.sun_family = AF_UNIX;
		strncpy(sockaddr.sockaddr_un.sun_path + 1, SERVER_LOCAL,
			sizeof(sockaddr.sockaddr_un.sun_path) - 1);

		sockaddr_len = sizeof(sockaddr.sockaddr_un);
	} else { /* AF_INET */
		sockaddr.sockaddr_in.sin_family = AF_INET;
		sockaddr.sockaddr_in.sin_port = htons(SERVER_PORT);
		sockaddr.sockaddr_in.sin_addr.s_addr = htonl(SERVER_IP);

		sockaddr_len = sizeof(sockaddr.sockaddr_in);
	}

	while (connect(sock->socket, (struct sockaddr *)&sockaddr, sockaddr_len) == -1)
		if (errno == EINPROGRESS)
			break;
		else if (errno == EAGAIN)
			continue;
		else
			return RC_ERR_CONNECTION;

	ev_io_init(&sock->io_socket_ev, connectEvent, sock->socket, EV_WRITE);
	sock->io_socket_ev.data = sock;
	ev_io_start(sock->ev, &sock->io_socket_ev);

	ev_timer_init(&sock->timer_socket_ev, connectTimeoutEvent, TIMEOUT_WRITE_REQUESTS, 0.);
	sock->timer_socket_ev.data = sock;
	ev_timer_start(sock->ev, &sock->timer_socket_ev);

	return RC_OK;
}

/** start an asynchonous accept
 *
 * Start an asynchonous accept and invoke a callback when the operation
 * completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_CONNECTION    Underlying socket was closed or blocking
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_accept_async(DMCONTEXT *socket)
{
	uint32_t rc;
	union {
		struct sockaddr_un sockaddr_un;
		struct sockaddr_in sockaddr_in;
	} sockaddr;

	socklen_t sockaddr_len;

	if (socket->socket <= 0)
		if ((rc = dm_create_socket(socket)) != RC_OK)
			return rc;

	memset(&sockaddr, 0, sizeof(sockaddr));
	if (socket->type == AF_UNIX) {
		sockaddr.sockaddr_un.sun_family = AF_UNIX;
		strncpy(sockaddr.sockaddr_un.sun_path + 1, SERVER_LOCAL,
			sizeof(sockaddr.sockaddr_un.sun_path) - 1);

		sockaddr_len = sizeof(sockaddr.sockaddr_un);
	} else { /* AF_INET */
		static int flag = 1;
		setsockopt(socket->socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

		sockaddr.sockaddr_in.sin_family = AF_INET;
		sockaddr.sockaddr_in.sin_port = htons(SERVER_PORT);
		sockaddr.sockaddr_in.sin_addr.s_addr = htonl(SERVER_IP);

		sockaddr_len = sizeof(sockaddr.sockaddr_in);
	}

	if (bind(socket->socket, (struct sockaddr *)&sockaddr, sockaddr_len))
		return RC_ERR_CONNECTION;

	fcntl(socket->socket, F_SETFD, fcntl(socket->socket, F_GETFD) | FD_CLOEXEC);

	if (listen(socket->socket, MAX_CONNECTIONS))
		return RC_ERR_CONNECTION;

	ev_io_init(&socket->io_socket_ev, acceptEvent, socket->socket, EV_READ);
	socket->io_socket_ev.data = socket;
	ev_io_start(socket->ev, &socket->io_socket_ev);

	return RC_OK;
}

static uint32_t
dm_connect_cb(DMCONFIG_EVENT event, DMCONTEXT *socket, void *userdata)
{
	uint32_t *rc = (uint32_t *)userdata;

	ev_break(socket->ev, EVBREAK_ONE);

	if (event == DMCONFIG_CONNECTED)
		*rc = RC_OK;
	else
		*rc = RC_ERR_CONNECTION;

	return RC_OK;
}

/** synchonous connect
 *
 * Synchonous connect, return status of underlying socket
 *
 * @param [in] socket   k       Pointer to socket context to connect on
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_CONNECTION    Underlying socket was closed or blocking
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_connect(DMCONTEXT *socket)
{
	uint32_t rc;
	void *save_userdata;
	DMCONFIG_CONNECTION_CB save_connection_cb;

	save_connection_cb = socket->connection_cb;
	socket->connection_cb = dm_connect_cb;

	save_userdata = socket->userdata;
	socket->userdata = &rc;

	if ((rc = dm_connect_async(socket)) != RC_OK)
		goto exit;

	ev_run(socket->ev, 0);

 exit:
	socket->connection_cb = save_connection_cb;
	socket->userdata = save_userdata;
	return rc;
}

/** synchonous accept
 *
 * Synchonous accept, return status of underlying socket
 *
 * @param [in] acceptSock       Pointer to socket context to accept on
 * @param [inout] sock          Pointer to socket context for the new socket context
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_CONNECTION    Underlying socket was closed or blocking
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_accept(DMCONTEXT *acceptSock, DMCONTEXT *sock)
{
	int fd;

	assert(acceptSock);
	assert(sock);

	if ((fd = accept(acceptSock->socket, NULL, NULL)) < 0)
		return RC_ERR_CONNECTION;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	dm_context_init(sock, acceptSock->ev,
			acceptSock->type,
			acceptSock->userdata, acceptSock->connection_cb, acceptSock->request_cb);
	sock->socket = fd;
	dm_init_events(sock);

	return RC_OK;
}

#if 0

/* move to generated client code */
dmclient_request_cb(DMCONTEXT *socket, DM_PACKET *pkt, DM2_AVPGRP *grp)
{
	switch (dm_packet_code(pkt)) {
	case CMD_CLIENT_ACTIVE_NOTIFY:
		process_active_notification(socket, pkt, &grp);
		break;

	case CMD_CLIENT_EVENT_BROADCAST:
		process_event_broadcast(socket, pkt, &grp);
		break;

	default:
		printf("Default Code: %d\n", dm_packet_code(pkt));
		break;
	}
}


/* move to generated client code */
static void
dmclient_reply(DMCONTEXT *socket, DM2_REQUEST_INFO *req, DM_PACKET *pkt, DM2_AVPGRP *grp)
{
	uint32_t rc;
	uint32_t reply_rc;

	if ((rc = dm_expect_uint32_type(&grp, AVP_RC, VP_TRAVELPING, &reply_rc)) != RC_OK) {
		CALLBACK(req->reply_cb, DMCONFIG_ERROR_READING, socket, req->user_data, rc, NULL);
		return;
	}

	/* TODO: handle this in the callback */
	if (reply_rc != RC_OK) {
		CALLBACK(req->reply_cb, DMCONFIG_ANSWER_READY, socket, req->userdata, reply_rc, NULL);
		return;

		/* clean up callback structures if necessary, so the read event is deleted */
		switch (req->code) {
		case CMD_SUBSCRIBE_NOTIFY:
			memset(&socket->callbacks.active_notification, 0, sizeof(socket->callbacks.active_notification));
			break;
		}

		goto cleanup;
	} else /* RC_OK */ {
		switch (req->code) {
		case CMD_UNSUBSCRIBE_NOTIFY:
			memset(&socket->callbacks.active_notification, 0, sizeof(socket->callbacks.active_notification));
			break;

		case CMD_ENDSESSION:
			/*
			 * allows the implicit abortion (deletion of read event -> event loop returns) of
			 * asynchronous processes (ping, active notify, etc)
			 */
			memset(&socket->callbacks, 0, sizeof(socket->callbacks));
			break;
		}
	}

	CALLBACK(req->reply_cb, DMCONFIG_ANSWER_READY, socket, req->userdata, RC_OK, &grp);
}

#endif

void
dm_async_cb(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	uint32_t rc;
	struct async_reply *reply = userdata;

	trace(":[%p] event: %d", socket, event);

	ev_break(socket->ev, EVBREAK_ONE);

	if (event != DMCONFIG_ANSWER_READY) {
		reply->rc = RC_ERR_MISC;
		return;
	}

	if (reply->answer) {
		if ((rc = dm_copy_avpgrp(reply->answer, grp)) != RC_OK) {
			reply->rc = rc;
			return;
		}
		grp = reply->answer;
	}

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &reply->rc)) != RC_OK) {
		reply->rc = rc;
		return;
	}

	return;
}
