/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DMCONTEXT_H
#define __DMCONTEXT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/queue.h>
#include <ev.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "dmmsg.h"
#include "libdmconfig/codes.h"

extern int dmconfig_debug_level;

#define SERVER_IP			0x7F000001		/* localhost */
#define ACCEPT_IP			SERVER_IP
#define SERVER_PORT			1100
#define SERVER_LOCAL			"DMSOCKET"

#define MAX_INT				0xFFFFFFFF		/* 2^32-1 */

#define SESSIONCTX_DEFAULT_TIMEOUT	(60*5)			/* 5 minutes */
#define SESSIONCTX_MAX_TIMEOUT		(60*10)			/* 10 minutes */

#define TIMEOUT_CHUNKS			3			/* 3s, while writing a request/answer */
#define TIMEOUT_READ_REQUESTS		SESSIONCTX_MAX_TIMEOUT	/* 10m, between reading requests/answers */
#define TIMEOUT_WRITE_REQUESTS		30			/* 30s, between writing requests/answers */

#define MAX_CONNECTIONS			100			/* maximum number of pending connections */


#define BUFFER_CHUNK_SIZE		(1024*8)		/* 8 kb */

		/* enums */

/**
 * request status enums
 */
typedef enum requestStatus {
	REQUEST_SHALL_WRITE,
	REQUEST_SHALL_READ
} REQUESTSTATUS;

/**
 * callback state enums
 */
typedef enum dmconfig_event {
	DMCONFIG_OK,
	DMCONFIG_ERROR_CONNECTING,
	DMCONFIG_ERROR_ACCEPTING,
	DMCONFIG_ERROR_WRITING,
	DMCONFIG_ERROR_READING,
	DMCONFIG_ANSWER_READY,
	DMCONFIG_CONNECTED,
	DMCONFIG_ACCEPTED,
	DMCONFIG_CLOSED,

	DMCONFIG_ERROR_CONNECT_TIMEOUT,
	DMCONFIG_ERROR_ACCEPT_TIMEOUT,
	DMCONFIG_ERROR_READ_TIMEOUT,
	DMCONFIG_ERROR_WRITE_TIMEOUT,
} DMCONFIG_EVENT;

		/* structures */

typedef struct requestInfo	REQUESTINFO;
typedef struct dmSocket		DMCONTEXT;

/**
 * dmconfig callback.
 */
typedef void (*DMCONFIG_CB) (DMCONTEXT *socket, DM_PACKET *pkg, DM2_AVPGRP *grp, void *userdata);
typedef void (*DMRESULT_CB) (DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata);

#define ONE_WAY  (1 << 0)
#define REQUEST  (1 << 1)
#define REPLY    (1 << 2)

/**
 * dmconfig connect callback.
 */
typedef uint32_t (*DMCONFIG_CONNECTION_CB) (DMCONFIG_EVENT event, DMCONTEXT *socket, void *userdata);


typedef struct requestInfo {
	TAILQ_ENTRY(requestInfo) entries;

	int flags;

	DMRESULT_CB reply_cb;
	void *userdata;

	REQUESTSTATUS status;
	uint32_t code;		/* FIXME: code/hopid may be ommitted if 'request' */
	uint32_t hopid;		/* is deallocated when the answer was received */

	DM_PACKET *packet;
} DM2_REQUEST_INFO;

typedef struct dm_io_context {
	ev_timer timer_ev;
	ev_io io_ev;

	DM_PACKET *packet;

	void *pos;
	ssize_t left;
} DM2_IOCONTEXT;

typedef struct dmSocket {
	int _ref;
	int type;
	int socket;
	uint32_t sessionid;

	TAILQ_HEAD(request_list, requestInfo) head;

	ev_timer timer_socket_ev;
	ev_io io_socket_ev;
	DM2_IOCONTEXT writeCtx;
	DM2_IOCONTEXT readCtx;
	struct ev_loop *ev;

	void *userdata;

	DMCONFIG_CONNECTION_CB connection_cb;
	DMCONFIG_CB request_cb;
} DMCONTEXT;

struct async_reply {
	uint32_t rc;
	DM2_AVPGRP *answer;
};

void dm_context_init(DMCONTEXT *dmCtx, struct ev_loop *base, int type,void *userdata, DMCONFIG_CONNECTION_CB connection_cb, DMCONFIG_CB request_cb);

static inline DMCONTEXT *dm_context_new(void);
static inline void dm_context_reference(DMCONTEXT *dmCtx);
static inline int dm_context_release(DMCONTEXT *dmCtx);

static inline int dm_context_get_socket(DMCONTEXT *dmCtx);
static inline void dm_context_set_sessionid(DMCONTEXT *dmCtx, uint32_t sessionid);
static inline uint32_t dm_context_get_sessionid(DMCONTEXT *dmCtx);
static inline void dm_context_set_event_base(DMCONTEXT *dmCtx, struct ev_loop *base);
static inline struct ev_loop *dm_context_get_event_base(DMCONTEXT *dmCtx);

static inline void dm_context_set_ev_loop(DMCONTEXT *dmCtx, struct ev_loop *loop);
static inline struct ev_loop *dm_context_get_ev_loop(DMCONTEXT *dmCtx);

uint32_t dm_connect_async(DMCONTEXT *socket);
uint32_t dm_accept_async(DMCONTEXT *socket);

uint32_t dm_connect(DMCONTEXT *socket);

void dm_context_shutdown(DMCONTEXT *sock, DMCONFIG_EVENT event);

uint32_t dm_accept(DMCONTEXT *acceptSock, DMCONTEXT *sock);
uint32_t dm_enqueue(DMCONTEXT *socket, DM2_REQUEST *req, int flags, DMRESULT_CB cb, void *data);
static inline uint32_t dm_enqueue_request(DMCONTEXT *socket, DM2_REQUEST *req, DMRESULT_CB cb, void *data);

//void dm_async_cb(DMCONFIG_EVENT event, DMCONTEXT *socket, void *userdata, uint32_t rc, DM2_AVPGRP *grp);
void dm_async_cb(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata);

/* context manipulation */

/** allocate and initialize a new socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev event_base to use for this context
 *
 * @ingroup API
 */
static inline DMCONTEXT*
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
static inline void
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
static inline int
dm_context_release(DMCONTEXT *dmCtx)
{
	int r;

	dmCtx->_ref--;
	r = dmCtx->_ref;

	if (dmCtx->_ref == 0)
		talloc_free(dmCtx);

	return r;
}

/** get the socket from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    Socket
 *
 * @ingroup API
 */
static inline int
dm_context_get_socket(DMCONTEXT *dmCtx)
{
	return dmCtx->socket;
}

/** set the userdata in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] userdata         New userdata
 *
 * @ingroup API
 */
static inline void
dm_context_set_userdata(DMCONTEXT *dmCtx, void *userdata)
{
	dmCtx->userdata = userdata;
}

/** get the userdata from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    Userdata
 *
 * @ingroup API
 */
static inline void *
dm_context_get_userdata(DMCONTEXT *dmCtx)
{
	return dmCtx->userdata;
}

/** set the session id in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] sessionid      New session id
 *
 * @ingroup API
 */
static inline void
dm_context_set_sessionid(DMCONTEXT *dmCtx, uint32_t sessionid)
{
	dmCtx->sessionid = sessionid;
}

/** get the session id from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    Current session id
 *
 * @ingroup API
 */
static inline uint32_t
dm_context_get_sessionid(DMCONTEXT *dmCtx)
{
	return dmCtx->sessionid;
}

/** set libev's libevent compatiblity event_base in a socket context
 *
 * set libev's libevent compatiblity event_base in a socket context,
 * this function is only for source code compatiblity with libevent
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] base           libev's event_base to use for this context
 *
 * @ingroup API
 */
static inline void
dm_context_set_event_base(DMCONTEXT *dmCtx, struct ev_loop *base)
{
	dmCtx->ev = (struct ev_loop *)base;
}

/** get libev's libevent compatiblity event_base from a socket context
 *
 * get libev's libevent compatiblity event_base from a socket context,
 * this function is only for source code compatiblity with libevent
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    libev's event_base from this context
 *
 * @ingroup API
 */
static inline struct ev_loop*
dm_context_get_event_base(DMCONTEXT *sock)
{
	return sock->ev;
}

/** set libev's ev_loop in a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @param [in] loop           libev's ev_loop to use for this context
 *
 * @ingroup API
 */
static inline void
dm_context_set_ev_loop(DMCONTEXT *dmCtx, struct ev_loop *loop)
{
	dmCtx->ev = loop;
}

/** get libev's ev_loop from a socket context
 *
 * @param [in] dmCtx          Pointer to socket context to work on
 * @retval                    libev's ev_loop from this context
 *
 * @ingroup API
 */
static inline struct ev_loop*
dm_context_get_ev_loop(DMCONTEXT *dmCtx)
{
	return dmCtx->ev;
}

static inline uint32_t
dm_enqueue_request(DMCONTEXT *socket, DM2_REQUEST *req, DMRESULT_CB cb, void *data)
{
	return dm_enqueue(socket, req, REQUEST, cb, data);
}

#endif
