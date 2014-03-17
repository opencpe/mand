/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <signal.h>

#include <sys/tree.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>

#include <sys/time.h>
#include <event.h>
#include <ev.h>

#include <sys/tree.h>

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmmsg.h"
#include "libdmconfig/codes.h"

#include "dm.h"
#include "dmd.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_index.h"
#include "dm_cache.h"
#include "dm_serialize.h"
#include "dm_cfgsessions.h"
#include "dm_strings.h"
#include "dm_cfg_bkrst.h"
#include "dm_notify.h"
#include "dm_dmconfig.h"
#include "dm_validate.h"
#include "utils/binary.h"

#include "dm_dmconfig_rpc_skel.h"

#define SDEBUG
#include "debug.h"

#define dm_debug(sid, format, ...) debug(": [#%08X] " format, sid, ## __VA_ARGS__)
#define dm_ENTER(sid) dm_debug(sid, "%s", "enter")
#define dm_EXIT(sid) dm_debug(sid, "%s, %d", "exit", __LINE__)

static int init_libdmconfig_socket(int type);

static void session_times_out(int fd __attribute__((unused)),
			      short type __attribute__((unused)), void *param);
static void requested_session_timeout(int fd __attribute__((unused)),
				      short type __attribute__((unused)), void *param);

static void freeSockCtx(SOCKCONTEXT *sockCtx);
static void async_free_sockCtx(EV_P __attribute__((unused)),
			       ev_async *w, int revents __attribute__((unused)));
static void disableSockCtx(SOCKCONTEXT *sockCtx);
static inline void threadDerefSockCtx(SOCKCONTEXT *sockCtx);

static void acceptEvent(int sfd __attribute__((unused)),
			short event __attribute__((unused)),
			void *arg __attribute__((unused)));
static void readEvent(int fd, short event, void *arg);
static inline int process_data(SOCKCONTEXT *sockCtx, COMMSTATUS status);
static inline int process_packet(SOCKCONTEXT *sockCtx, OBJ_GROUP *obj);
static void writeEvent(int fd, short event, void *arg);

static int register_answer(uint32_t code, uint32_t hopid, uint32_t endid,
			   uint32_t rc, DM_AVPGRP *avps, SOCKCONTEXT *sockCtx);
static int register_packet(DM_REQUEST *packet, SOCKCONTEXT *sockCtx);

static int reset_writeEvent(SOCKCONTEXT *sockCtx);
static void async_reset_writeEvent(EV_P __attribute__((unused)),
				   ev_async *w, int revents __attribute__((unused)));

static uint32_t process_start_session(SOCKCONTEXT *sockCtx, uint32_t flags,
				      uint32_t hopid, struct timeval timeout);
static uint32_t process_switch_session(SOCKCONTEXT *sockCtx, uint32_t flags,
				       uint32_t hopid, SESSION *le, struct timeval timeout);

		/* session handling: session list and misc. variables  */

			/* libdmconfig clients get sessionIds in the range of 1 to MAX_INT */
static uint32_t			session_counter;
uint32_t			cfg_sessionid = 0;	/* 0 means there's no (libdmconfig) configure session */

static int			accept_socket;
static struct event_base	*evbase;

static SESSION			*session_head = NULL;
static REQUESTED_SESSION	*reqsession_head = NULL;
static SOCKCONTEXT		*socket_head = NULL;

static struct event		clientConnection;
int				libdmconfigSocketType;

static uint32_t			req_hopid;
static uint32_t			req_endid;

		/* static as only one of these operations is running at once */

static pthread_mutex_t		dmconfig_mutex = PTHREAD_MUTEX_INITIALIZER; /* generic dmconfig mutex */

static pthread_t		main_thread;

SESSION *
lookup_session(uint32_t sessionid)
{
	SESSION *ret;

	dm_ENTER(sessionid);

	if (!sessionid) {
		dm_EXIT(sessionid);
		return NULL;
	}

	for (ret = session_head->next;
			ret && ret->sessionid != sessionid; ret = ret->next);

	dm_EXIT(sessionid);
	return ret;
}

static int
init_libdmconfig_socket(int type)
{
	int fd;

	ENTER();

			/* binding and listening cannot block */

	if (type == AF_UNIX) {
		static struct sockaddr_un sockaddr;

		if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			EXIT();
			return -1;
		}

		memset(&sockaddr, 0, sizeof(sockaddr));

		sockaddr.sun_family = AF_UNIX;
		strncpy(sockaddr.sun_path + 1, SERVER_LOCAL,
			sizeof(sockaddr.sun_path) - 1);

		if (bind(fd, &sockaddr, sizeof(struct sockaddr_un))) {
			close(fd);
			EXIT();
			return -1;
		}
	} else { /* AF_INET */
		static struct sockaddr_in sockaddr;
		static int flag = 1;

		if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
			EXIT();
			return -1;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag))) {
			close(fd);
			EXIT();
			return -1;
		}

		memset(&sockaddr, 0, sizeof(sockaddr));

		sockaddr.sin_family = AF_INET;
		sockaddr.sin_port = htons(SERVER_PORT);
		sockaddr.sin_addr.s_addr = htonl(ACCEPT_IP);

		if (bind(fd, &sockaddr, sizeof(struct sockaddr_in))) {
			close(fd);
			EXIT();
			return -1;
		}
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	if (listen(fd, MAX_CONNECTIONS)) {
		close(fd);
		EXIT();
		return -1;
	}

	EXIT();
	return fd;
}

uint8_t
init_libdmconfig_server(struct event_base *base)
{
	SOCKCONTEXT *old_socket_head = socket_head; /* required since this function may be called
						       for cleanup purposes even if threads still depend on some sockCtx
						       in this case we don't want to allocate socket_head or free it after 'abort:' */

	ENTER();

	evbase = base;
	main_thread = pthread_self();

	if ((accept_socket = init_libdmconfig_socket(libdmconfigSocketType)) == -1) {
		EXIT();
		return 1;
	}

	/* initiate session counter & hop2hop/end2end ids (random value between 1 and MAX_INT) */

	srand((unsigned int)time(NULL));
	session_counter = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
	req_hopid = req_endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;

	/* init the list heads / talloc contexts */

	if (!(session_head = talloc(NULL, SESSION)) ||
	    !(reqsession_head = talloc(NULL, REQUESTED_SESSION)) ||
	    (!old_socket_head && !(socket_head = talloc(NULL, SOCKCONTEXT))))
		goto abort;

	memset(session_head, 0, sizeof(SESSION));
	memset(reqsession_head, 0, sizeof(REQUESTED_SESSION));
	memset(socket_head, 0, sizeof(SOCKCONTEXT));

	event_set(&clientConnection, accept_socket, EV_READ | EV_PERSIST,
		  acceptEvent, NULL);
	event_base_set(evbase, &clientConnection);

	if (event_add(&clientConnection, NULL)) /* it listens the whole time, so no timeout */
		goto abort;

	EXIT();
	return 0;

abort:

	talloc_free(session_head);
	talloc_free(reqsession_head);
	if (!old_socket_head)
		talloc_free(socket_head);

	close(accept_socket);
	EXIT();
	return 1;
}

static void
acceptEvent(int sfd __attribute__((unused)), short event __attribute__((unused)),
	    void *arg __attribute__((unused)))
{
	int			fd, flags;

	SOCKCONTEXT		*sockCtx;
	COMMCONTEXT		*readCtx, *writeCtx;

	ENTER();

	if ((fd = accept(accept_socket, NULL, NULL)) == -1) {
		EXIT();
		return;
	}

	flags = 1;
	/* NOTE: this will fail if the socket is not a TCP socket, but that's nothing to worry */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flags, sizeof(flags));

	if ((flags = fcntl(fd, F_GETFL)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
		close(fd);
		EXIT();
		return;
	}

	if (!(sockCtx = talloc(socket_head, SOCKCONTEXT))) {
		close(fd);
		EXIT();
		return;
	}
	memset(sockCtx, 0, sizeof(SOCKCONTEXT));

	sockCtx->refcnt = 1;
	sockCtx->fd = fd;

	readCtx = &sockCtx->readCtx;
	writeCtx = &sockCtx->writeCtx;

	event_set(&readCtx->event, fd, EV_READ | EV_PERSIST, readEvent, sockCtx);
	event_base_set(evbase, &readCtx->event);

	event_set(&writeCtx->event, fd, EV_WRITE | EV_PERSIST, writeEvent, sockCtx);
	event_base_set(evbase, &writeCtx->event);

	if (pthread_mutex_init(&sockCtx->lock, NULL) ||
	    event_add(&readCtx->event, NULL)) {	/* currently, no read timeouts */
		talloc_free(sockCtx);		/* unless a request was partially read */
		close(fd);
		EXIT();
		return;
	}

	ev_async_init(&sockCtx->sync, async_reset_writeEvent);
	ev_async_start((struct ev_loop *)evbase, &sockCtx->sync);

	ev_async_init(&sockCtx->free, async_free_sockCtx);
	ev_async_start((struct ev_loop *)evbase, &sockCtx->free);
	sockCtx->free.data = sockCtx;

	LD_INSERT(socket_head, sockCtx);

	EXIT();
}

/*
 * "garbage collect" a sockCtx
 */

static void
freeSockCtx(SOCKCONTEXT *sockCtx)
{
	ENTER();

	pthread_mutex_destroy(&sockCtx->lock);

	ev_async_stop((struct ev_loop *)evbase, &sockCtx->sync);
	ev_async_stop((struct ev_loop *)evbase, &sockCtx->free);

	talloc_free(sockCtx->readCtx.req);

	L_FOREACH(REQUESTED_SESSION, cur, reqsession_head)
		if (cur->sockCtx == sockCtx) {
			REQUESTED_SESSION *prev = cur->prev;

			if ((prev->next = cur->next))
				cur->next->prev = prev;

			event_del(&cur->timeout);
			talloc_free(cur);

			cur = prev;
		}

	shutdown(sockCtx->fd, SHUT_RDWR);
	close(sockCtx->fd);

	if (sockCtx->notifySession)
		unsubscribeNotify(sockCtx->notifySession);

	LD_FREE(sockCtx); /* also frees the answer list & outgoing requests and
			     removes sockCtx from the sockets list */

	EXIT();
}

static void
async_free_sockCtx(EV_P __attribute__((unused)),
		   ev_async *w, int revents __attribute__((unused)))
{
	freeSockCtx((SOCKCONTEXT*)w->data);
}

/*
 * called from the main thread in case of CONNRESETs and related errors
 * to derefernce & possibly "garbage collect" a sockCtx.
 */

static void
disableSockCtx(SOCKCONTEXT *sockCtx)
{
	ENTER();

	pthread_mutex_lock(&sockCtx->lock);

			/* don't bother us with read/write callbacks again */
	event_del(&sockCtx->readCtx.event);
	event_del(&sockCtx->writeCtx.event);

			/* "deinitialize" so threads won't add events again */
	memset(&sockCtx->readCtx.event, 0, sizeof(struct event));
	memset(&sockCtx->writeCtx.event, 0, sizeof(struct event));

	if (!--sockCtx->refcnt) {
		pthread_mutex_unlock(&sockCtx->lock);
		freeSockCtx(sockCtx);
	} else
		pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
}

/*
 * called from non-main threads to derefernce & possibly "garbage collect" a sockCtx.
 * don't care about events since "garbage collection" is only done when the main
 * thread dereferenced the sockCtx and thus already deleted them
 */

static inline void
threadDerefSockCtx(SOCKCONTEXT *sockCtx)
{
	pthread_mutex_lock(&sockCtx->lock);

	if (!--sockCtx->refcnt) {
		pthread_mutex_unlock(&sockCtx->lock);
		ev_async_send((struct ev_loop *)evbase, &sockCtx->free);
	} else
		pthread_mutex_unlock(&sockCtx->lock);
}

void
unsubscribeNotify(SESSION *le)
{
	free_slot(le->notify.slot);
	le->notify.clientSockCtx->notifySession = NULL;
	memset(&le->notify, 0, sizeof(NOTIFY_INFO));
}

static void
readEvent(int fd, short event, void *arg)
{
	SOCKCONTEXT	*sockCtx = arg;

	COMMSTATUS	status;
	uint8_t		alreadyRead = 0;

	debug("(): [%d]: %d", fd, event);

	do {
				/* NOTE: theoretically locking shouldn't be necessary here
				 * since readCtx is only accessed in the main thread and
				 * the read request is a root talloc context
				 */
		pthread_mutex_lock(&sockCtx->lock);
		event_aux_dmRead(fd, event, &sockCtx->readCtx, &alreadyRead, &status);
		pthread_mutex_unlock(&sockCtx->lock);

		debug(": alreadyRead: %d, status: %d", alreadyRead, status);
	} while (process_data(sockCtx, status));

	EXIT();
}

/*
 * TODO: split processRequest into inline functions (the switch statement) and
 * maybe merge the rest with 'readEvent'
 */

static inline int
process_data(SOCKCONTEXT *sockCtx, COMMSTATUS status)
{
	COMMCONTEXT		*ctx;

	char			*path = NULL;
	char			*dum = NULL;
	char			*buf = NULL;

	OBJ_GROUP		obj;
	struct timeval		timeout;

	memset(&obj, 0, sizeof(obj));

	pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking not necessary here */

	debug("(): [%d]: %d", sockCtx->fd, status);
	ctx = &sockCtx->readCtx;
	obj.req = ctx->req;

	pthread_mutex_unlock(&sockCtx->lock);

	switch (status) {
	case CONNRESET:
		goto reaccept;
	case INCOMPLETE:
		timeout.tv_sec = TIMEOUT_CHUNKS;
		timeout.tv_usec = 0;

		pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking not necessary here */
		if (event_add(&ctx->event, &timeout)) {	/* reduce readEvent's timeout */
			pthread_mutex_unlock(&sockCtx->lock);
			goto server_err;
		}
		pthread_mutex_unlock(&sockCtx->lock);

		EXIT();
		return 0;
	case NOTHING:
		EXIT();
		return 0;
	case COMPLETE:
		break;
	default:	/* ERROR */
		goto server_err;
	}

	switch (process_packet(sockCtx, &obj)) {

	case RC_OK:
		pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking unnecessary here */
						/* currently, no read timeouts */
						/* unless a request was partially read */
		if (event_add(&ctx->event, NULL)) {	/* reset readEvent's timeout */
			pthread_mutex_unlock(&sockCtx->lock);
			goto server_err;
		}
		pthread_mutex_unlock(&sockCtx->lock);

		EXIT();
		return 1;

	case RC_ERR_ALLOC:

server_err:
		/* critical error: deallocate everything properly */

		L_FOREACH(SESSION, cur, session_head) {
			if (cur->notify.slot)
				unsubscribeNotify(cur);
			event_del(&cur->timeout);
		}
		talloc_free(session_head);
		session_head = NULL;

		L_FOREACH(REQUESTED_SESSION, cur, reqsession_head)
			event_del(&cur->timeout);
		talloc_free(reqsession_head);
		reqsession_head = NULL;

		L_FOREACH(SOCKCONTEXT, cur, socket_head)
			disableSockCtx(cur);
		/* at least try to free the socket_head if no threads depend on any sockCtx */
		if (!socket_head->next) {
			talloc_free(socket_head);
			socket_head = NULL;
		}

		free(dum);
		free(path);
		free(buf);

		event_del(&clientConnection);
		shutdown(accept_socket, SHUT_RDWR);
		close(accept_socket);

		/* restart server */

		init_libdmconfig_server(evbase);

		EXIT();
		return 0;


	default:
reaccept:
		/* protocol/communication errors (including terminated peer connections) */
		/* there's no need to reset everything */

		disableSockCtx(sockCtx);

		EXIT();
		return 0;
	}
}

static inline int
process_packet(SOCKCONTEXT *sockCtx, OBJ_GROUP *obj)
{
	DMC_REQUEST req;
	DM2_AVPGRP grp;
	DM_OBJ *answer = NULL;
	int r;
	uint32_t rc = RC_OK;

	/* request read successfully */

	dm_init_packet(&obj->req->packet, &grp);

	req.hop2hop = dm_hop2hop_id(&obj->req->packet);
	req.end2end = dm_end2end_id(&obj->req->packet);
	req.code = dm_packet_code(&obj->req->packet);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Received %s:\n",
		dm_packet_flags(obj->req->packet) & CMD_FLAG_REQUEST ?
							"request" : "answer");
	dump_dm_packet(obj->req);
	dm_request_reset_avp(obj->req);
#endif

	/* don't accept client answers currently */
	if (!(dm_packet_flags(&obj->req->packet) & CMD_FLAG_REQUEST)) {
		debug("(): error, not a request");
		return RC_ERR_CONNECTION;
	}

	if ((r = dm_expect_uint32_type(&grp, AVP_SESSIONID, VP_TRAVELPING, &req.sessionid)) != RC_OK)
		return r;

	dm_debug(req.sessionid, "session");

	/* TODO: cleanup, WTF is used for....*/
	if (req.code != CMD_GET_PASSIVE_NOTIFICATIONS && req.sessionid &&	/* reset_timeout_obj validates the sessionId, too */
	    reset_timeout_obj(req.sessionid)) {					/* except for POLLs because they don't reset the timeout */
		rc = RC_ERR_INVALID_SESSIONID;
		debug("(): error, invalid session id");
	} else
		rc = rpc_dmconfig_switch(sockCtx, &req, &grp, &answer);

	if (rc != RC_ERR_ALLOC)
		/* the command evaluation has to set "code" and "answer"
		   (or leave it preinitialized to RC_OK, NULL) */
		if (register_answer(req.code, req.hop2hop, req.end2end, rc, answer, sockCtx))
			return RC_ERR_ALLOC;

	return rc;
}

uint32_t
process_request_session(struct event_base *base, SOCKCONTEXT *sockCtx,
			uint32_t dm_code, uint32_t hopid, uint32_t sessionid,
			DM2_AVPGRP *grp)
{
	uint32_t	rc;
	uint32_t	code;
	uint8_t		header_flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	uint32_t	flags;
	SESSION		*le;

	struct timeval	timeout_session;

	dm_ENTER(sessionid);

	switch (dm_code) {
	case CMD_SWITCHSESSION:
		if (!(le = lookup_session(sessionid))) {
			dm_EXIT(sessionid);
			return register_answer(CMD_SWITCHSESSION, hopid,
					       hopid, RC_ERR_INVALID_SESSIONID,
					       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
		}
		break;
	case CMD_STARTSESSION:
		if (sessionid) {
			dm_EXIT(sessionid);
			return register_answer(CMD_STARTSESSION, hopid,
					       hopid, RC_ERR_INVALID_SESSIONID,
					       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
		}

		le = NULL;
	}

	if ((rc = dm_expect_uint32_type(grp, AVP_UINT32, VP_TRAVELPING, &flags)) != RC_OK)
		return rc;

	timeout_session.tv_sec = SESSIONCTX_DEFAULT_TIMEOUT;
	timeout_session.tv_usec = 0;

	while ((rc = dm_expect_avp(grp, &code, &vendor_id, &data, &len)) == RC_OK) {
		if (len != sizeof(DM_TIMEVAL)) {
			dm_EXIT(sessionid);
			return RC_ERR_MISC;
		}

		switch (code) {
		case AVP_TIMEOUT_SESSION:
			timeout_session = dm_get_timeval_avp(data);

			if ((!timeout_session.tv_sec && !timeout_session.tv_usec) ||
			    timeout_session.tv_sec > SESSIONCTX_MAX_TIMEOUT) {
				timeout_session.tv_sec = SESSIONCTX_MAX_TIMEOUT;
				timeout_session.tv_usec = 0;
			}

			break;

		case AVP_TIMEOUT_REQUEST: {
			REQUESTED_SESSION	*session;
			struct timeval		timeout_delay;

			if (!(flags & CMD_FLAG_CONFIGURE) ||
			    getCfgSessionStatus() == CFGSESSION_INACTIVE)
				break;

			timeout_delay = dm_get_timeval_avp(data);

					/* maximum timeout, don't allow an indefinite delay */
			if ((!timeout_delay.tv_sec && !timeout_delay.tv_usec) ||
			    timeout_delay.tv_sec > SESSIONCTX_MAX_TIMEOUT) {
				timeout_delay.tv_sec = SESSIONCTX_MAX_TIMEOUT;
				timeout_delay.tv_usec = 0;
			}

			if (!(session = talloc(reqsession_head,
					       REQUESTED_SESSION))) {
				dm_EXIT(sessionid);
				return RC_ERR_ALLOC;
			}

			LD_INSERT(reqsession_head, session);

			session->flags = flags;
			session->hopid = hopid;
			session->code = dm_code;
			session->sockCtx = sockCtx;
			session->session = le;

			memcpy(&session->timeout_session, &timeout_session,
			       sizeof(struct timeval));

			evtimer_set(&session->timeout, requested_session_timeout,
				    session);
			event_base_set(base, &session->timeout);
			evtimer_add(&session->timeout, &timeout_delay);

			dm_debug(sessionid, "CMD: %s (requested)\n",
			      le ? "SWITCH SESSION" : "START SESSION");

			dm_EXIT(sessionid);
			return RC_OK;
		}

		default:
			dm_EXIT(sessionid);
			return RC_ERR_MISC;
		}
	}

	if (flags & CMD_FLAG_CONFIGURE &&
	    getCfgSessionStatus() != CFGSESSION_INACTIVE) {	/* a config session is already open */
		dm_EXIT(sessionid);
		return register_answer(dm_code, hopid, hopid,
				       RC_ERR_CANNOT_OPEN_CFGSESSION, NULL,
				       sockCtx) ? RC_ERR_ALLOC : RC_OK;
	}

	if (le) {	/* switch sessions only */
		if (flags & CMD_FLAG_CONFIGURE)
			dm_debug(sessionid, "CMD: SWITCH SESSION (r/w to cfg) (id = %08X)\n", le->sessionid);
		else if (le->sessionid == cfg_sessionid)
			dm_debug(sessionid, "CMD: SWITCH SESSION (cfg to r/w) (id = %08X)\n", le->sessionid);
		else {
			dm_EXIT(sessionid);
			return register_answer(CMD_SWITCHSESSION, hopid,
					       hopid, RC_ERR_REQUIRES_CFGSESSION,
					       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
		}

		dm_EXIT(sessionid);
		return process_switch_session(sockCtx, flags, hopid, le, timeout_session);
	}

	debug(": CMD: START SESSION (id = %08X)\n", session_counter);

	dm_EXIT(sessionid);
	return process_start_session(sockCtx, flags, hopid, timeout_session);
}

static uint32_t
process_start_session(SOCKCONTEXT *sockCtx, uint32_t flags, uint32_t hopid,
		      struct timeval timeout)
{
	SESSION		*le;
	DM_AVPGRP	*answer;

	uint32_t	rc;

	dm_ENTER(session_counter);

	if (!(le = talloc(session_head, SESSION))) {
		dm_EXIT(session_counter);
		return RC_ERR_ALLOC;
	}
	memset(le, 0, sizeof(SESSION));

	LS_INSERT(session_head, le);

	le->sockCtx = sockCtx;
	le->sessionid = session_counter;
	le->flags = flags;

	evtimer_set(&le->timeout, session_times_out, le);
	event_base_set(evbase, &le->timeout);

	memcpy(&le->timeout_session, &timeout, sizeof(struct timeval));
	evtimer_add(&le->timeout, &le->timeout_session);

	if (!(answer = new_dm_avpgrp(NULL)) ||
	    dm_avpgrp_add_uint32(NULL, &answer, AVP_SESSIONID, 0,
				   VP_TRAVELPING, session_counter)) {
		talloc_free(answer);
		dm_EXIT(session_counter);
		return RC_ERR_ALLOC;
	}

	rc = register_answer(CMD_STARTSESSION, hopid, hopid, RC_OK, answer, sockCtx);
	talloc_free(answer);
	if (rc) {
		dm_EXIT(session_counter);
		return RC_ERR_ALLOC;
	}

	if (flags & CMD_FLAG_CONFIGURE) {
		cfg_sessionid = session_counter;
		setCfgSessionStatus(CFGSESSION_ACTIVE_LIBDMCONFIG);
	}

	if (session_counter == MAX_INT)
		session_counter = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
	else
		session_counter++;

	dm_EXIT(le->sessionid);
	return RC_OK;
}

static uint32_t
process_switch_session(SOCKCONTEXT *sockCtx, uint32_t flags,
		       uint32_t hopid, SESSION *le, struct timeval timeout)
{
	dm_ENTER(le->sessionid);

	if (flags & CMD_FLAG_CONFIGURE) {
		cfg_sessionid = le->sessionid;
		setCfgSessionStatus(CFGSESSION_ACTIVE_LIBDMCONFIG);
	} else {
		cfg_sessionid = 0;
		setCfgSessionStatus(CFGSESSION_INACTIVE);
	}

	le->flags = flags;

	memcpy(&le->timeout_session, &timeout, sizeof(struct timeval));
	evtimer_add(&le->timeout, &le->timeout_session);

	dm_EXIT(le->sessionid);
	return register_answer(CMD_SWITCHSESSION, hopid, hopid, RC_OK,
			       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
}

		/* processes another pending config session request or resets the status */

void
processRequestedSessions(void)
{
	REQUESTED_SESSION *session;

	ENTER();

	if (!reqsession_head) {	/* server was not yet initiated */
		EXIT();
		return;
	}

	if (!(session = reqsession_head->next)) {
		cfg_sessionid = 0;
		EXIT();
		return;
	}

	if (session->session) {
		dm_debug(session->session->sessionid, "CFGSESSION TERMINATED: %s", "SWITCH SESSION (r/w to cfg)");

		if (process_switch_session(session->sockCtx, session->flags,
					   session->hopid, session->session,
					   session->timeout_session)) {
			/* fatal error, restart libdmconfig */
			EXIT();
			return;
		}
	} else {
		dm_debug(session_counter, "CFGSESSION TERMINATED: %s", "START SESSION");

		if (process_start_session(session->sockCtx, session->flags,
					  session->hopid, session->timeout_session)) {
			/* fatal error, restart libdmconfig */
			EXIT();
			return;
		}
	}

	event_del(&session->timeout);

	if ((reqsession_head->next = session->next))
		session->next->prev = reqsession_head;

	EXIT();
}

		/* called by CMD_ENDSESSION requests and by timeout events */
uint32_t
process_end_session(uint32_t sessionid) {
	SESSION *cur, *le;

	dm_ENTER(sessionid);

			/* find predecessor of session with sessionid */
	for (cur = session_head;
		cur->next && cur->next->sessionid != sessionid; cur = cur->next);
	le = cur->next;

	if (!le) {
		dm_EXIT(sessionid);
		return RC_ERR_MISC;
	}
			/* remove from session list */
	cur->next = le->next;

			/* also take care of the pending timeout event */
	evtimer_del(&le->timeout);

	if (le->notify.slot)
		unsubscribeNotify(le);

	talloc_free(le);

	if (sessionid == cfg_sessionid)
		setCfgSessionStatus(CFGSESSION_INACTIVE);
	else {
		exec_actions_pre();
		exec_actions();
		exec_pending_notifications();
	}

	dm_EXIT(sessionid);
	return RC_OK;
}

static int
register_answer(uint32_t code, uint32_t hopid, uint32_t endid,
		uint32_t rc, DM_AVPGRP *avps, SOCKCONTEXT *sockCtx)
{
	DM_AVPGRP	*completegrp;
	DM_REQUEST	*answer;
	int		r;

	ENTER();

	pthread_mutex_lock(&sockCtx->lock);

	debug(": [%d]: %d, rc = %u", sockCtx->fd, code, rc);

	if (!(answer = new_dm_request(sockCtx, code, 0, APP_ID, hopid, endid)) ||
	    !(completegrp = new_dm_avpgrp(answer)) ||
	    dm_avpgrp_add_uint32(answer, &completegrp, AVP_RC, 0,
	    			   VP_TRAVELPING, rc) ||
	    (avps && dm_avpgrp_add_avpgrp(answer, &completegrp, AVP_CONTAINER,
	    				    0, VP_TRAVELPING, avps)) ||
	    build_dm_request(sockCtx, &answer, completegrp)) {
		talloc_free(answer);
		pthread_mutex_unlock(&sockCtx->lock);
		EXIT();
		return 1;
	}

	talloc_free(completegrp);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Send answer:\n");
	dump_dm_packet(answer);
	dm_request_reset_avp(answer);
#endif

	if ((r = register_packet(answer, sockCtx)))
		talloc_free(answer);

	pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
	return r;
}

int
register_request(uint32_t code, DM_AVPGRP *avps, SOCKCONTEXT *sockCtx)
{
	DM_REQUEST	*request;
	int		r;

	ENTER();

	pthread_mutex_lock(&sockCtx->lock);
	pthread_mutex_lock(&dmconfig_mutex);

	if (req_hopid == MAX_INT)
		req_hopid = req_endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
	else
		req_hopid = ++req_endid;

	r = !(request = new_dm_request(sockCtx, code, CMD_FLAG_REQUEST,
					 APP_ID, req_hopid, req_endid)) ||
	    build_dm_request(sockCtx, &request, avps);
	pthread_mutex_unlock(&dmconfig_mutex);
	if (r) {
		talloc_free(request);
		pthread_mutex_unlock(&sockCtx->lock);
		EXIT();
		return 1;
	}

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Send request:\n");
	dump_dm_packet(request);
	dm_request_reset_avp(request);
#endif

	if ((r = register_packet(request, sockCtx)))
		talloc_free(request);

	pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
	return r;
}

		/* sockCtx->lock always locked when register_packet is called */
static int
register_packet(DM_REQUEST *packet, SOCKCONTEXT *sockCtx)
{
	int r = 0;

	debug(": [%d]: %p", sockCtx->fd, packet);

	packet->info.next = NULL;

	if (!sockCtx->send_queue.tail) {
		/* queue is empty */
		sockCtx->send_queue.head = sockCtx->send_queue.tail = packet;
	} else {
		sockCtx->send_queue.tail->info.next = packet;
		sockCtx->send_queue.tail = packet;
	}

	if (pthread_equal(pthread_self(), main_thread))
		r = reset_writeEvent(sockCtx);
	else
		ev_async_send((struct ev_loop *)evbase, &sockCtx->sync);

	EXIT();
	return r;
}

static int
reset_writeEvent(SOCKCONTEXT *sockCtx)
{
	COMMCONTEXT	*ctx = &sockCtx->writeCtx;
	int		r = 0;

	ENTER();

	if (event_initialized(&ctx->event) &&				/* don't add the event if it was deleted due to a CONNRESET/reaccept */
	    !event_pending(&ctx->event, EV_WRITE | EV_PERSIST, NULL)) {	/* ensures that we don't overwrite its current timeout */
		struct timeval timeout = {
			.tv_sec = TIMEOUT_WRITE_REQUESTS,
			.tv_usec = 0
		};

		r = event_add(&ctx->event, &timeout);
	}

	EXIT();
	return r;
}

static void
async_reset_writeEvent(EV_P __attribute__((unused)),
		       ev_async *w, int revents __attribute__((unused)))
{
	SOCKCONTEXT *sockCtx = (SOCKCONTEXT *)w;

			/* NOTE: theoretically locking shouldn't be necessary here
			 * since the write event is only accessed in the main thread
			 */
	pthread_mutex_lock(&sockCtx->lock);
	reset_writeEvent(sockCtx);
	pthread_mutex_unlock(&sockCtx->lock);
}

static void
writeEvent(int fd, short event, void *arg)
{
	SOCKCONTEXT	*sockCtx = arg;
	COMMCONTEXT	*ctx;
	COMMSTATUS	status = COMPLETE;

	struct timeval	timeout;

	debug(": [%d]: %d", fd, event);

	pthread_mutex_lock(&sockCtx->lock);

	ctx = &sockCtx->writeCtx;

	for (;;) {
		if (!ctx->req) {
			ctx->req = sockCtx->send_queue.head;
			if (!ctx->req) {
				/* queue was empty */
				pthread_mutex_unlock(&sockCtx->lock);
				EXIT();	/* FIXME (and below): more extensive cleanup */
				return;
			}

			sockCtx->send_queue.head = ctx->req->info.next;
			ctx->req->info.next = NULL;

			if (!sockCtx->send_queue.head)
				/* queue is now empty, we dequeued the tail packet */
				sockCtx->send_queue.tail = NULL;
		}

		debug(": [%d]: %p", fd, ctx->req);
		event_aux_dmWrite(fd, event, ctx, &status);
		debug(": [%d]: status: %d", fd, status);

		switch (status) {
		case COMPLETE: {
			talloc_free(ctx->req);
			ctx->req = NULL;
			ctx->buffer = NULL;

			if (!sockCtx->send_queue.head) {
				event_del(&ctx->event);
				pthread_mutex_unlock(&sockCtx->lock);
				EXIT();
				return;
			}

			timeout.tv_sec = TIMEOUT_WRITE_REQUESTS;
			timeout.tv_usec = 0;

			if (event_add(&ctx->event, &timeout)) {	/* increase writeEvent's timeout */
				pthread_mutex_unlock(&sockCtx->lock);
				EXIT();
				return;
			}

			break;
		}
		case INCOMPLETE:
			timeout.tv_sec = TIMEOUT_CHUNKS;
			timeout.tv_usec = 0;

			event_add(&ctx->event, &timeout);	/* reduce writeEvent's timeout */
		case NOTHING:
			pthread_mutex_unlock(&sockCtx->lock);
			EXIT();
			return;
		default:	/* connection reset or error */
			pthread_mutex_unlock(&sockCtx->lock);
			disableSockCtx(sockCtx);

			if (status == ERROR) {
				debug(": [%d]: error", fd);
				event_del(&clientConnection);
				shutdown(accept_socket, SHUT_RDWR);
				close(accept_socket);

				/* this is almost certainly wrong */
				init_libdmconfig_server(evbase);
			}

			EXIT();
			return;
		}
	}

	/* shouldn't be reached */
	EXIT();
}

/*
	session timeout cb function
*/

static void
session_times_out(int fd __attribute__((unused)),
		  short type __attribute__((unused)), void *param)
{
	SESSION *le = param;
	uint32_t sessionid = le->sessionid;

	dm_ENTER(sessionid);
	dm_debug(sessionid, "SESSION TIMEOUT: END SESSION");

			/* ignore return value - if the sessionId was already invalid,
			   it's unnecessary to terminate it */
	process_end_session(sessionid);

	dm_EXIT(sessionid);
}

static void
requested_session_timeout(int fd __attribute__((unused)),
			  short type __attribute__((unused)), void *param)
{
	REQUESTED_SESSION *session = param;

	ENTER();

	debug(": %s SESSION (requested) timed out\n",
	      session->session ? "SWITCH" : "START");

	if (register_answer(session->code, session->hopid, session->hopid,
			    RC_ERR_CANNOT_OPEN_CFGSESSION, NULL, session->sockCtx)) {
		EXIT();
		return;
	}

	LD_FREE(session);

	EXIT();
}

int
reset_timeout_obj(uint32_t sessionid)
{
	SESSION *le;

	dm_ENTER(sessionid);

	if (!(le = lookup_session(sessionid))) {
		EXIT();
		return 1;
	}

	evtimer_add(&le->timeout, &le->timeout_session);

	dm_EXIT(sessionid);
	return 0;
}

void dm_event_broadcast(const dm_selector sel, enum dm_action_type type)
{
	static const uint32_t event_types[] = {
		[DM_ADD]    = EVENT_INSTANCE_CREATED,
		[DM_CHANGE] = EVENT_INSTANCE_DELETED,
		[DM_DEL]    = EVENT_PARAMETER_CHANGED
	};
	DM_AVPGRP	*grp, *dummy;
	char		*path;
	char		buffer[MAX_PARAM_NAME_LEN];
	SESSION		*sess;
	int		r;

	ENTER();

	if (!(path = dm_sel2name(sel, buffer, sizeof(buffer))) ||
	    !(grp = new_dm_avpgrp(NULL))) {
		talloc_free(grp);
		EXIT();
		return;
	}
	debug("(): event broadcast: %s, type: %d\n", path, type);

	if (dm_avpgrp_add_uint32(grp, &grp, AVP_EVENT_TYPE, 0, VP_TRAVELPING, event_types[type]) ||
	    dm_avpgrp_add_string(grp, &grp, AVP_PATH, 0, VP_TRAVELPING, path)) {
		talloc_free(grp);
		EXIT();
		return;
	}

	if (!(dummy = new_dm_avpgrp(NULL))) {
		talloc_free(grp);
		return;
	}

	r = dm_avpgrp_add_avpgrp(NULL, &dummy, AVP_CONTAINER, 0,
				   VP_TRAVELPING, grp);
	talloc_free(grp);
	if (r) {
		talloc_free(dummy);
		return;
	}

	for (sess = session_head->next; sess; sess = sess->next) {
		if (!sess->sockCtx)
			continue;

		register_request(CMD_CLIENT_EVENT_BROADCAST, dummy, sess->sockCtx);
	}

	talloc_free(dummy);
	EXIT();
}

/* API v2 */

uint32_t dm_expect_path_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, dm_selector *value)
{
	size_t size;
	void *data;
	char path[1024];
	uint32_t r;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size)) != RC_OK)
		return r;

	if (size >= sizeof(path))
		return RC_ERR_MISC;

	strncpy(path, data, size);
	if (!dm_name2sel(path, value))
		return RC_ERR_MISC;

	return RC_OK;
}
