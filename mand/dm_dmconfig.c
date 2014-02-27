/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#define SDEBUG
#include "debug.h"

#define dm_debug(sid, format, ...) debug(": [#%08X] " format, sid, ## __VA_ARGS__)
#define dm_ENTER(sid) dm_debug(sid, "%s", "enter")
#define dm_EXIT(sid) dm_debug(sid, "%s, %d", "exit", __LINE__)

#define UINT16_DIGITS	6	/* log(2^16-1)+1 */

static int init_libdmconfig_socket(int type);
static SESSION *lookup_session(uint32_t sessionid);

static void session_times_out(int fd __attribute__((unused)),
			      short type __attribute__((unused)), void *param);
static void requested_session_timeout(int fd __attribute__((unused)),
				      short type __attribute__((unused)), void *param);

static void freeSockCtx(SOCKCONTEXT *sockCtx);
static void async_free_sockCtx(EV_P __attribute__((unused)),
			       ev_async *w, int revents __attribute__((unused)));
static void disableSockCtx(SOCKCONTEXT *sockCtx);
static inline void threadDerefSockCtx(SOCKCONTEXT *sockCtx);

static inline void unsubscribeNotify(SESSION *le);

static DM_RESULT build_client_info(void *ctx, DM_AVPGRP **grp,
				   struct dm_value_table *clnt);

static void acceptEvent(int sfd __attribute__((unused)),
			short event __attribute__((unused)),
			void *arg __attribute__((unused)));
static void readEvent(int fd, short event, void *arg);
static inline int processRequest(SOCKCONTEXT *sockCtx, COMMSTATUS status);
static void writeEvent(int fd, short event, void *arg);

static int register_answer(uint32_t code, uint32_t hopid, uint32_t endid,
			   uint32_t rc, DM_AVPGRP *avps, SOCKCONTEXT *sockCtx);
static int register_request(uint32_t code, DM_AVPGRP *avps, SOCKCONTEXT *sockCtx);
static int register_packet(DM_REQUEST *packet, SOCKCONTEXT *sockCtx);

static int reset_writeEvent(SOCKCONTEXT *sockCtx);
static void async_reset_writeEvent(EV_P __attribute__((unused)),
				   ev_async *w, int revents __attribute__((unused)));

static DM_AVPGRP *build_notify_events(struct notify_queue *queue, int level);
static void dmconfig_notify_cb(void *data, struct notify_queue *queue);

static DM_RESULT dmconfig_avp2value(OBJ_AVPINFO *header,
				    const struct dm_element *elem,
				    DM_VALUE *value);
static DM_RESULT dmconfig_value2avp(GET_GRP_CONTAINER *container,
				    const struct dm_element *elem,
				    const DM_VALUE val);

static DM_RESULT dmconfig_set_cb(void *data, const dm_selector sel,
				 const struct dm_element *elem,
				 struct dm_value_table *base,
				 const void *value __attribute__((unused)),
				 DM_VALUE *st);
static DM_RESULT dmconfig_get_cb(void *data,
				 const dm_selector sb __attribute__((unused)),
				 const struct dm_element *elem,
				 const DM_VALUE val);
static int dmconfig_list_cb(void *data, CB_type type, dm_id id,
			    const struct dm_element *elem,
			    const DM_VALUE value __attribute__((unused)));
static DM_RESULT dmconfig_retrieve_enums_cb(void *data,
					    const dm_selector sb __attribute__((unused)),
					    const struct dm_element *elem,
					    const DM_VALUE val __attribute__((unused)));

static inline uint32_t process_request_session(struct event_base *base,
					       SOCKCONTEXT *sockCtx,
					       uint32_t dm_code, uint32_t hopid,
					       uint32_t sessionid,
					       DM_AVPGRP *grp);
static uint32_t process_start_session(SOCKCONTEXT *sockCtx, uint32_t flags,
				      uint32_t hopid, struct timeval timeout);
static uint32_t process_switch_session(SOCKCONTEXT *sockCtx, uint32_t flags,
				       uint32_t hopid, SESSION *le, struct timeval timeout);
static int process_end_session(uint32_t sessionid);

		/* session handling: session list and misc. variables  */

			/* libdmconfig clients get sessionIds in the range of 1 to MAX_INT */
static uint32_t			session_counter;
static uint32_t			cfg_sessionid = 0;	/* 0 means there's no (libdmconfig) configure session */

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

static SESSION *
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

static inline void
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
	} while (processRequest(sockCtx, status));

	EXIT();
}

/*
 * TODO: split processRequest into inline functions (the switch statement) and
 * maybe merge the rest with 'readEvent'
 */

static inline int
processRequest(SOCKCONTEXT *sockCtx, COMMSTATUS status)
{
	COMMCONTEXT		*ctx;

	char			*path = NULL;
	char			*dum = NULL;
	char			*buf = NULL;

	OBJ_GROUP		obj;

	uint32_t		hop2hop;
	uint32_t		end2end;

	OBJ_AVPINFO		header;
	uint32_t		dm_code;

	uint32_t		code = RC_OK;

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

		/* request read successfully */

	hop2hop = dm_hop2hop_id(&obj.req->packet);
	end2end = dm_end2end_id(&obj.req->packet);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Received %s:\n",
		dm_packet_flags(&obj.req->packet) & CMD_FLAG_REQUEST ?
							"request" : "answer");
	dump_dm_packet(obj.req);
	dm_request_reset_avp(obj.req);
#endif

				/* don't accept client answers currently */
	if (!(dm_packet_flags(&obj.req->packet) & CMD_FLAG_REQUEST)) {
		debug("(): error, not a request");
		goto reaccept;
	}

	if (dm_request_get_avp(obj.req, &header.code, &header.flags,
				 &header.vendor_id, &header.data, &header.len)) {
		debug("(): error, could not decode avp's");
		goto server_err;
	}
	if (header.code != AVP_SESSIONID || header.len != sizeof(uint32_t)) {
		debug("(): error, no or invalid session id");
		goto reaccept;
	}

	obj.sessionid = dm_get_uint32_avp(header.data);
	dm_debug(obj.sessionid, "session");

	if (!dm_request_get_avp(obj.req, &header.code, &header.flags,
				  &header.vendor_id, &header.data,
				  &header.len)) {
		if (header.code != AVP_CONTAINER) {
			debug("(): error, avp is not a container");
			goto reaccept;
		}
		if (!(obj.reqgrp = dm_decode_avpgrp(obj.req, header.data,
						      header.len))) {
			debug("(): error, could no decode avp container");
			goto server_err;
		}
	}

	dm_code = dm_packet_code(&obj.req->packet);

	if (dm_code != CMD_GET_PASSIVE_NOTIFICATIONS && obj.sessionid &&	/* reset_timeout_obj validates the sessionId, too */
	    reset_timeout_obj(obj.sessionid)) {					/* except for POLLs because they don't reset the timeout */
		code = RC_ERR_INVALID_SESSIONID;
		debug("(): error, invalid session id");
	} else {	/* must... not... use... a... GO... TO... */
		switch (dm_code) {
		case CMD_STARTSESSION:
		case CMD_SWITCHSESSION: {
			uint32_t rc;

			if (!(rc = process_request_session(evbase, sockCtx, dm_code, hop2hop, obj.sessionid, obj.reqgrp)))
				goto increase_timeout;
			if (rc == RC_ERR_ALLOC)
				goto server_err;
			goto reaccept;
		}

		case CMD_ENDSESSION:
			dm_debug(obj.sessionid, "CMD: %s... ", "END SESSION");

			if (process_end_session(obj.sessionid))
				code = RC_ERR_INVALID_SESSIONID;

			break;

		case CMD_SESSIONINFO: {
			SESSION *le;

			dm_debug(obj.sessionid, "CMD: %s... ", "GET SESSION INFO");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!(obj.answer_grp = new_dm_avpgrp(obj.req)) ||
			    dm_avpgrp_add_uint32(obj.req, &obj.answer_grp, AVP_UINT32, 0, VP_TRAVELPING, le->flags))
				goto server_err;

			break;
		}

		case CMD_CFGSESSIONINFO: {
			SESSION *le;

			dm_debug(obj.sessionid, "CMD: %s... ", "GET CONFIGURE SESSION INFO");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!(le = lookup_session(cfg_sessionid))) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_dm_avpgrp(obj.req)) ||
			    dm_avpgrp_add_uint32(obj.req, &obj.answer_grp, AVP_SESSIONID, 0, VP_TRAVELPING, cfg_sessionid) ||
			    dm_avpgrp_add_uint32(obj.req, &obj.answer_grp, AVP_UINT32, 0, VP_TRAVELPING, le->flags) ||
			    dm_avpgrp_add_timeval(obj.req, &obj.answer_grp, AVP_TIMEVAL, 0, VP_TRAVELPING, le->timeout_session))
				goto server_err;

			break;
		}

		case CMD_SUBSCRIBE_NOTIFY: {
			SESSION		*le;
			int		slot;

			dm_debug(obj.sessionid, "CMD: %s... ", "SUBSCRIBE NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (le->notify.slot || (slot = alloc_slot(dmconfig_notify_cb, le)) == -1) {
				code = RC_ERR_CANNOT_SUBSCRIBE_NOTIFY;
				break;
			}

			le->notify.slot = slot;
			le->notify.clientSockCtx = sockCtx;

			pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking unnecessary here */
			sockCtx->notifySession = le;
			pthread_mutex_unlock(&sockCtx->lock);

			break;
		}

		case CMD_UNSUBSCRIBE_NOTIFY: {
			SESSION	*le;

			dm_debug(obj.sessionid, "CMD: UNSUBSCRIBE NOTIFY... ");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			unsubscribeNotify(le);

			break;
		}

		case CMD_PARAM_NOTIFY: {
			uint32_t	notify;
			SESSION		*le;

			dm_debug(obj.sessionid, "CMD: %s... ", "PARAM NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_BOOL || header.len != sizeof(uint8_t))
				goto reaccept;

			notify = dm_get_uint8_avp(header.data) ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_CONTAINER || !header.len)
				goto reaccept;

			if (!(obj.avpgrp = dm_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

			while (!dm_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				dm_selector sb, *sel;

				if (header.code != AVP_PATH)
					goto reaccept;
				if (!header.len) {
					code = RC_ERR_MISC;
					break;
				}

				if (!(path = strndup(header.data, header.len)))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\" (%s)", "PARAM NOTIFY",
					 path, notify == ACTIVE_NOTIFY ? "active" : "passive");

				sel = dm_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				if (dm_set_notify_by_selector(sb, le->notify.slot, notify) != DM_OK) {
					code = RC_ERR_MISC;
					break;
				}
			}

			break;
		}

		case CMD_RECURSIVE_PARAM_NOTIFY: {
			uint32_t	notify;
			SESSION		*le;
			dm_selector	sb, *sel;

			dm_debug(obj.sessionid, "CMD: %s... ", "RECURSIVE PARAM NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_BOOL || header.len != sizeof(uint8_t))
				goto reaccept;

			notify = dm_get_uint8_avp(header.data) ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_CONTAINER || !header.len)
				goto reaccept;

			if (!(obj.avpgrp = dm_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

			if (dm_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_PATH)
				goto reaccept;

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"... ", "RECURSIVE PARAM NOTIFY", path);

			sel = dm_name2sel(*path ? path : "InternetGatewayDevice", &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (dm_set_notify_by_selector_recursive(sb, le->notify.slot, notify) != DM_OK)
				code = RC_ERR_MISC;

			break;
		}

		case CMD_GET_PASSIVE_NOTIFICATIONS: {
			SESSION			*le;
			struct notify_queue	*queue;

			dm_debug(obj.sessionid, "CMD: %s... ", "GET PASSIVE NOTIFICATIONS");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			queue = get_notify_queue(le->notify.slot);
			obj.answer_grp = build_notify_events(queue, PASSIVE_NOTIFY);
			if (!obj.answer_grp) {
				/*
				 * NOTE: we cannot discern real errors from empty queues
				 * simply assume it was an empty queue (empty answer grp expected)
				 */
				if (!(obj.answer_grp = new_dm_avpgrp(obj.req)))
					goto server_err;
				break;
			}
			if (!talloc_reference(obj.req, obj.answer_grp))
				goto server_err;

			break;
		}

		case CMD_DB_ADDINSTANCE: {
			dm_selector	sb, *sel;
			dm_id	id;

			dm_debug(obj.sessionid, "CMD: %s", "DB ADD INSTANCE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB ADD INSTANCE", path);

			sel = dm_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;

			id = dm_get_uint16_avp(header.data);

			dm_debug(obj.sessionid, "CMD: %s id = 0x%hX", "DB ADD INSTANCE", id);

			if (!dm_add_instance_by_selector(sb, &id)) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_dm_avpgrp(obj.req)))
				goto server_err;
			if (dm_avpgrp_add_uint16(obj.req, &obj.answer_grp, AVP_UINT16, 0,
						   VP_TRAVELPING, id))
				goto server_err;

			break;
		}

		case CMD_DB_DELINSTANCE: {	/* improvised: check whether this is a table */
			dm_selector sb, *sel;

			dm_debug(obj.sessionid, "CMD: %s", "DB DELETE INSTANCE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB DELETE INSTANCE", path);

			sel = dm_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (!dm_del_table_by_selector(sb)) {
				code = RC_ERR_MISC;
				break;
			}

			break;
		}

		case CMD_DB_SET: {	/* iterate grouped AVPs & display changes */
			SET_GRP_CONTAINER container = {
				.header = &header,
				.session = lookup_session(obj.sessionid)
			};

			dm_debug(obj.sessionid, "CMD: %s", "DB SET");

			if (!container.session) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			while (!dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				dm_selector	sb, *sel;
				DM_RESULT	rc;

				if (header.code != AVP_CONTAINER)
					goto reaccept;

				if (!(obj.avpgrp = dm_decode_avpgrp(obj.req, header.data, header.len)) ||
				    dm_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
							&header.vendor_id, &header.data, &header.len))
					goto server_err;
				if (header.code != AVP_PATH)
					goto reaccept;
				if (!header.len) {
					code = RC_ERR_MISC;
					break;
				}

				if (!(path = strndup(header.data, header.len)))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB SET", path);

				sel = dm_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				if (dm_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
							&header.vendor_id, &header.data, &header.len))
					goto server_err;

				if ((rc = dm_get_value_ref_by_selector_cb(sb, &container /* ...tweak... */, &container, dmconfig_set_cb)) == DM_OOM)
					goto server_err;
				if (rc != DM_OK) {
					code = RC_ERR_MISC;
					break;
				}
				talloc_free(obj.avpgrp);
			}

			break;
		}
		case CMD_DB_GET: {	/* iterate path AVPs & send answers */
			GET_BY_SELECTOR_CB get_value = cfg_sessionid && obj.sessionid == cfg_sessionid ?
							dm_cache_get_value_by_selector_cb : dm_get_value_by_selector_cb;
			GET_GRP_CONTAINER container;

			dm_debug(obj.sessionid, "CMD: %s", "DB GET");

			container.ctx = obj.req;
			if (!(container.grp = new_dm_avpgrp(container.ctx)))
				goto server_err;

			while (!dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				dm_selector	sb, *sel;
				DM_RESULT	rc;

				if (header.code != AVP_TYPE_PATH  && header.len <= sizeof(uint32_t))
					goto reaccept;

				container.type = dm_get_uint32_avp(header.data);

				if (!(path = strndup((char*)header.data + sizeof(uint32_t), header.len - sizeof(uint32_t))))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\", type: %d", "DB GET", path, container.type);

				sel = dm_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				if ((rc = get_value(sb, T_ANY, &container, dmconfig_get_cb)) == DM_OOM)
					goto server_err;
				if (rc != DM_OK) {
					code = RC_ERR_MISC;
					break;
				}
			}

			obj.answer_grp = container.grp;

			break;
		}

		case CMD_DB_LIST: {
			LIST_CTX	list_ctx;
			int		level;

			dm_debug(obj.sessionid, "CMD: %s", "DB LIST");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			memset(&list_ctx, 0, sizeof(LIST_CTX));
			list_ctx.ctx = obj.req;
			if (!(list_ctx.grp = new_dm_avpgrp(list_ctx.ctx)))
				goto server_err;

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			level = dm_get_uint16_avp(header.data);
			list_ctx.max_level = level ? : DM_SELECTOR_LEN;

			dm_debug(obj.sessionid, "CMD: %s %u", "DB LIST", level);

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;

			if (header.len) {
				dm_selector sb, *sel;

				if (!(path = strndup(header.data, header.len)))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB LIST", path);

				sel = dm_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				list_ctx.firstone = 1;	/* there has to be a better solution to ignore the first one */
				if (!dm_walk_by_selector_cb(sb, level ? level + 1 : DM_SELECTOR_LEN,
							       &list_ctx, dmconfig_list_cb)) {
					code = RC_ERR_MISC;
					break;
				}
			} else {
				/** InternetGatewayDevice */
				if (!dm_walk_by_selector_cb((dm_selector) {cwmp__InternetGatewayDevice, 0},
							       list_ctx.max_level, &list_ctx, dmconfig_list_cb)) {
					code = RC_ERR_MISC;
					break;
				}
			}

			obj.answer_grp = list_ctx.grp;

			break;
		}

		case CMD_DB_RETRIEVE_ENUMS: {
			dm_selector	sb, *sel;
			DM_RESULT	rc;

			dm_debug(obj.sessionid, "CMD: %s", "DB RETRIEVE ENUMS");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB RETRIEVE ENUMS", path);

			sel = dm_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_dm_avpgrp(obj.req)))
				goto server_err;

			if ((rc = dm_get_value_by_selector_cb(sb, T_ENUM, &obj, dmconfig_retrieve_enums_cb)) == DM_OOM)
				goto server_err;
			if (rc != DM_OK) {
				talloc_free(obj.answer_grp);
				obj.answer_grp = NULL;
				code = RC_ERR_MISC;
			}

			break;
		}

		case CMD_DB_DUMP: {
			long tsize;
			size_t r = 0;
			FILE *tf;

			dm_debug(obj.sessionid, "CMD: %s", "DB DUMP");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB DUMP", path);

			tf = tmpfile();
			if (!tf)
				goto server_err;

			if (path && *path)
				dm_serialize_element(tf, path, S_ALL);
			else
				dm_serialize_store(tf, S_ALL);

			free(path);
			path = NULL;

			tsize = ftell(tf);
			fseek(tf, 0, SEEK_SET);

			if (!tsize) {
				fclose(tf);
				code = RC_ERR_MISC;
				break;
			}

			buf = malloc(tsize);
			if (buf)
				r = fread(buf, tsize, 1, tf);
			fclose(tf);
			if (r != 1)
				goto server_err;

			if (!(obj.answer_grp = new_dm_avpgrp(obj.req)))
				goto server_err;
			if (dm_avpgrp_add_raw(obj.req, &obj.answer_grp, AVP_STRING, 0,
						VP_TRAVELPING, buf, tsize))
				goto server_err;
			free(buf);
			buf = NULL;

			break;
		}

		case CMD_DB_SAVE:			/* saves running config to persistent storage */
			dm_debug(obj.sessionid, "CMD: %s", "DB SAVE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (obj.sessionid == cfg_sessionid &&
			    !cache_is_empty()) {		/* cache not empty */
				code = RC_ERR_MISC;
				break;
			}

			dm_save();

			break;

		case CMD_DB_COMMIT: {
			SESSION *le;

			/* commits cache to running config and tries to apply changes */
			dm_debug(obj.sessionid, "CMD: %s", "DB COMMIT");

			if (!(le = lookup_session(obj.sessionid)) || obj.sessionid != cfg_sessionid) {
				code = RC_ERR_REQUIRES_CFGSESSION;
				break;
			}

			if (cache_validate()) {
				exec_actions_pre();
				cache_apply(le->notify.slot ? : -1);
				exec_actions();
				exec_pending_notifications();
			} else {
				code = RC_ERR_MISC;
				break;
			}

			break;
		}

		case CMD_DB_CANCEL:
			dm_debug(obj.sessionid, "CMD: %s", "DB CANCEL");

			if (!cfg_sessionid || obj.sessionid != cfg_sessionid) {
				code = RC_ERR_REQUIRES_CFGSESSION;
				break;
			}

			cache_reset();

			break;

		case CMD_DB_FINDINSTANCE: {
			dm_selector			sb, *sel;
			dm_id			param;
			DM_VALUE			value;

			struct dm_instance_node	*inst;

			const struct dm_table	*kw;
			DM_RESULT			rc;

			dm_debug(obj.sessionid, "CMD: %s", "DB FINDINSTANCE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

					/* parameter/value container */
			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_CONTAINER)
				goto reaccept;
			if (!(obj.avpgrp = dm_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

					/* path of table */
			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB FINDINSTANCE", path);

			sel = dm_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

					/* find table structure */
			if (!(kw = dm_get_object_table_by_selector(sb))) {
				code = RC_ERR_MISC;
				break;
			}

					/* name of paramter to check (last part of path) */
			if (dm_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if ((param = dm_get_element_id_by_name(header.data, header.len, kw)) == DM_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: parameter id: %u", "DB FINDINSTANCE", param);

					/* value to look for (type is AVP code) */
			if (dm_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s: value", "DB FINDINSTANCE");
			if ((rc = dmconfig_avp2value(&header, kw->table + param - 1, &value)) == DM_OOM)
				goto server_err;
			if (rc != DM_OK) {
				code = RC_ERR_MISC;
				break;
			}

			inst = find_instance_by_selector(sb, param, kw->table[param - 1].type, &value);
			dm_free_any_value(kw->table + param - 1, &value);
			if (!inst) {
				code = RC_ERR_MISC;
				break;
			}
			dm_debug(obj.sessionid, "CMD: %s: answer: %u", "DB FINDINSTANCE", inst->instance);

			if (!(obj.answer_grp = new_dm_avpgrp(obj.req)))
				goto server_err;
			if (dm_avpgrp_add_uint16(obj.req, &obj.answer_grp, AVP_UINT16, 0,
						   VP_TRAVELPING, inst->instance))
				goto server_err;

			break;
		}

		case CMD_DEV_CONF_SAVE:
			dm_debug(obj.sessionid, "CMD: %s", "DEV CONFSAVE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: DEV CONFSAVE - Remote Server: %s", dum);
			if (save_conf(dum))
				code = RC_ERR_MISC;
			free(dum);
			dum = NULL;

			break;

		case CMD_DEV_CONF_RESTORE:
			dm_debug(obj.sessionid, "CMD: %s", "DEV CONFRESTORE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (dm_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: DEV CONFRESTORE - Remote Server: %s", dum);
			if (restore_conf(dum))
				code = RC_ERR_MISC;
			free(dum);
			dum = NULL;

			break;

		default:
			dm_debug(obj.sessionid, "CMD: unknown/invalid: %d", dm_code);
			goto reaccept;
		}
	}

	/* FIXME: replace the goto with proper RC code handling */
	/* ie. split up "switch" into separate functions; don't confuse error conditions and error codes sent in answer */

			/* the command evaluation has to set "code" and "answer_grp"
			   (or leave it preinitialized to RC_OK, NULL) */
	if (register_answer(dm_code, hop2hop, end2end, code, obj.answer_grp, sockCtx))
		goto server_err;

increase_timeout:

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

reaccept:		/* protocol/communication errors (including terminated peer connections) */
			/* there's no need to reset everything */

	disableSockCtx(sockCtx);

	EXIT();
	return 0;

server_err:		/* critical error: deallocate everything properly */

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
}

static inline uint32_t
process_request_session(struct event_base *base, SOCKCONTEXT *sockCtx,
			uint32_t dm_code, uint32_t hopid, uint32_t sessionid,
			DM_AVPGRP *grp)
{
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

	if (dm_avpgrp_get_avp(grp, &code, &header_flags, &vendor_id,
				&data, &len)) {
		dm_EXIT(sessionid);
		return RC_ERR_ALLOC;
	}

	if (code != AVP_UINT32 || len != sizeof(uint32_t)) {
		dm_EXIT(sessionid);
		return RC_ERR_MISC;
	}

	flags = dm_get_uint32_avp(data);

	timeout_session.tv_sec = SESSIONCTX_DEFAULT_TIMEOUT;
	timeout_session.tv_usec = 0;

	while (!dm_avpgrp_get_avp(grp, &code, &header_flags, &vendor_id,
				    &data, &len)) {
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
		return process_switch_session(sockCtx, flags, hopid, le,
					      timeout_session);
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
static int
process_end_session(uint32_t sessionid) {
	SESSION *cur, *le;

	dm_ENTER(sessionid);

			/* find predecessor of session with sessionid */
	for (cur = session_head;
		cur->next && cur->next->sessionid != sessionid; cur = cur->next);
	le = cur->next;

	if (!le) {
		dm_EXIT(sessionid);
		return 1;
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
	return 0;
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

static int
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

static DM_AVPGRP *
build_notify_events(struct notify_queue *queue, int level)
{
	struct notify_item	*next;

	DM_AVPGRP		*grp;
	int			haveEvent = 0;

	ENTER(": level=%d", level);

	if (!(grp = new_dm_avpgrp(NULL))) {
		EXIT();
		return NULL;
	}

	for (struct notify_item *item = RB_MIN(notify_queue, queue);
	     item;
	     item = next) {
		char			buffer[MAX_PARAM_NAME_LEN];
		char			*path;

		DM_AVPGRP		*event;

		next = RB_NEXT(notify_queue, queue, item);

		if (item->level != level)
			continue;

			/* active notification */

		haveEvent = 1;

		if (!(path = dm_sel2name(item->sb, buffer, sizeof(buffer))) ||
		    !(event = new_dm_avpgrp(grp))) {
			talloc_free(grp);
			EXIT();
			return NULL;
		}

		switch (item->type) {
		case NOTIFY_ADD:
			debug(": instance added: %s", path);

			if (dm_avpgrp_add_uint32(grp, &event, AVP_NOTIFY_TYPE, 0,
						   VP_TRAVELPING,
						   NOTIFY_INSTANCE_CREATED) ||
			    dm_avpgrp_add_string(grp, &event, AVP_PATH, 0,
			    	    		   VP_TRAVELPING, path)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}
			break;

		case NOTIFY_DEL:
			debug(": instance removed: %s", path);

			if (dm_avpgrp_add_uint32(grp, &event, AVP_NOTIFY_TYPE, 0,
						   VP_TRAVELPING,
						   NOTIFY_INSTANCE_DELETED) ||
			    dm_avpgrp_add_string(grp, &event, AVP_PATH, 0,
			    	    		   VP_TRAVELPING, path)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}
			break;

		case NOTIFY_CHANGE: {
			GET_GRP_CONTAINER container = {
				.ctx = event,
				.type = AVP_UNKNOWN
			};
			struct dm_element *elem;

			debug(": parameter changed: %s", path);

			if (dm_avpgrp_add_uint32(grp, &event, AVP_NOTIFY_TYPE, 0,
						   VP_TRAVELPING,
						   NOTIFY_PARAMETER_CHANGED)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}

			if (!(container.grp = new_dm_avpgrp(container.ctx)) ||
			    dm_get_element_by_selector(item->sb, &elem) == T_NONE ||
			    dmconfig_value2avp(&container, elem, item->value) != DM_OK) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}

			if (dm_avpgrp_add_uint32_string(grp, &event, AVP_TYPE_PATH, 0,
							  VP_TRAVELPING,
							  container.type, path) ||
			    dm_avpgrp_insert_avpgrp(grp, &event, container.grp)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}
			break;
		}
		}

		if (dm_avpgrp_add_avpgrp(NULL, &grp, AVP_CONTAINER, 0,
					   VP_TRAVELPING, event)) {
			talloc_free(grp);
			EXIT();
			return NULL;
		}

		talloc_free(event);
		RB_REMOVE(notify_queue, queue, item);
		free(item);
	}

	if (!haveEvent) {
		talloc_free(grp);
		EXIT();
		return NULL;
	}

	EXIT();
	return grp;
}

static void
dmconfig_notify_cb(void *data, struct notify_queue *queue)
{
	SESSION			*session = data;
	NOTIFY_INFO		*notify = &session->notify;

	DM_AVPGRP		*grp, *dummy;
	int			r;

	dm_ENTER(session->sessionid);

	grp = build_notify_events(queue, ACTIVE_NOTIFY);
	if (!grp) {
		dm_EXIT(session->sessionid);
		return;
	}
	if (!(dummy = new_dm_avpgrp(NULL))) {
		talloc_free(grp);
		dm_EXIT(session->sessionid);
		return;
	}

	r = dm_avpgrp_add_avpgrp(NULL, &dummy, AVP_CONTAINER, 0,
				   VP_TRAVELPING, grp);
	talloc_free(grp);
	if (r) {
		talloc_free(dummy);
		dm_EXIT(session->sessionid);
		return;
	}

	register_request(CMD_CLIENT_ACTIVE_NOTIFY, dummy, notify->clientSockCtx);

	talloc_free(dummy);
	dm_EXIT(session->sessionid);
}

static DM_RESULT
dmconfig_avp2value(OBJ_AVPINFO *header, const struct dm_element *elem,
		   DM_VALUE *value)
{
	char		*dum = NULL;
	DM_RESULT	r = DM_OK;

	ENTER();

	if (!elem) {
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	memset(value, 0, sizeof(DM_VALUE));

	if (header->code == AVP_UNKNOWN) {
		if (!(dum = strndup(header->data, header->len))) {
			EXIT();
			return DM_OOM;
		}

		switch (elem->type) {
		case T_BASE64:
		case T_BINARY: {	/* dm_string2value cannot be used since it treats T_BASE64 and T_BINARY differently */
			unsigned int len;
			binary_t *n;

			/* this is going to waste some bytes.... */
			len = ((header->len + 4) * 3) / 4;

			n = malloc(sizeof(binary_t) + len);
			if (!n) {
				r = DM_OOM;
				break;
			}

			debug(": base64 string: %d, buffer: %u", (int)header->len, len);
			n->len = dm_from64((unsigned char *)dum, (unsigned char *)n->data);
			debug(": base64 result: %d", n->len);
			r = dm_set_binary_value(value, n);
			free(n);

			break;
		}

		default:
			debug(": = %s\n", dum);
			r = dm_string2value(elem, dum, 0, value);
		}
	} else {
		switch (elem->type) {
		case T_STR:	/* FIXME: strndup could be avoided by introducing a new dm_set_lstring_value... */
			if (header->code != AVP_STRING)
				r = DM_INVALID_TYPE;
			else if (!(dum = strndup(header->data, header->len)))
				r = DM_OOM;
			else {
				debug(": = \"%s\"\n", dum);
				r = dm_set_string_value(value, dum);
			}

			break;

		case T_BINARY:
		case T_BASE64:
			if (header->code != AVP_BINARY)
				r = DM_INVALID_TYPE;
			else {
				debug(": = binary data...\n"); /* FIXME: hex dump for instance... */
				r = dm_set_binary_data(value, header->len, header->data);
			}

			break;

		case T_SELECTOR:
			if (header->code != AVP_PATH)
				r = DM_INVALID_TYPE;
			else if (!(dum = strndup(header->data, header->len)))
				r = DM_OOM;
			else {
				dm_selector sel;

				debug(": = \"%s\"\n", dum);

				if (*dum) {
					if (!dm_name2sel(dum, &sel)) {
						r = DM_INVALID_VALUE;
						break;
					}
				} else
					memset(&sel, 0, sizeof(dm_selector));

				r = dm_set_selector_value(value, sel);
			}

			break;

		case T_IPADDR4: {
			int		af;
			struct in_addr	addr;

			if (header->code != AVP_ADDRESS)
				r = DM_INVALID_TYPE;
			else if (!dm_get_address_avp(&af, &addr, header->data) ||
				af != AF_INET)
				r = DM_INVALID_VALUE;
			else {
				debug(": = %s\n", inet_ntoa(addr));

				set_DM_IP4(*value, addr);
			}

			break;
		}

		case T_ENUM: {
			int enumid;

			switch (header->code) {
			case AVP_ENUM:
				if (!(dum = strndup(header->data, header->len)))
					r = DM_OOM;
				else if ((enumid = dm_enum2int(&elem->u.e,
								  dum)) == -1)
					r = DM_INVALID_VALUE;
				else {
					debug(": = %s (%d)\n", dum, enumid);
					set_DM_ENUM(*value, enumid);
				}

				break;
			case AVP_ENUMID:
				enumid = dm_get_int32_avp(header->data);
				if (enumid < 0 || enumid >= elem->u.e.cnt) {
					r = DM_INVALID_VALUE;
				} else {
					debug(": = %s (%d)\n",
					      dm_int2enum(&elem->u.e, enumid),
					      enumid);
					set_DM_ENUM(*value, enumid);
				}

				break;
			default:
				r = DM_INVALID_TYPE;
			}

			break;
		}

		case T_INT:
			if (header->code != AVP_INT32)
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT(*value,
					   dm_get_int32_avp(header->data));
				debug(": = %d\n", DM_INT(*value));
			}

			break;

		case T_UINT:
			if (header->code != AVP_UINT32)
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT(*value,
					    dm_get_uint32_avp(header->data));
				debug(": = %u\n", DM_UINT(*value));
			}

			break;

		case T_INT64:
			if (header->code != AVP_INT64)
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT64(*value,
					     dm_get_int64_avp(header->data));
				debug(": = %" PRIi64 "\n", DM_INT64(*value));
			}

			break;

		case T_UINT64:
			if (header->code != AVP_UINT64)
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT64(*value,
					      dm_get_uint64_avp(header->data));
				debug(": = %" PRIu64 "\n", DM_UINT64(*value));
			}

			break;

		case T_BOOL:
			if (header->code != AVP_BOOL)
				r = DM_INVALID_TYPE;
			else {
				set_DM_BOOL(*value,
					    dm_get_uint8_avp(header->data));
				debug(": = %d\n", DM_BOOL(*value));
			}

			break;

		case T_DATE:
			if (header->code != AVP_DATE)
				r = DM_INVALID_TYPE;
			else {
				set_DM_TIME(*value,
					    dm_get_time_avp(header->data));
				debug(": = (%d) %s", (int)DM_TIME(*value),
				      ctime(DM_TIME_REF(*value)));
			}

			break;

		case T_TICKS:
			switch (header->code) {
			case AVP_ABSTICKS: /* FIXME: has to be converted? */
			case AVP_RELTICKS:
				set_DM_TICKS(*value,
					     dm_get_int64_avp(header->data));
				debug(": = %" PRItick "\n", DM_TICKS(*value));
				break;
			default:
				r = DM_INVALID_TYPE;
			}

			break;

		default:		/* includes T_COUNTER which is non-writable */
			r = DM_INVALID_TYPE;
		}
	}

	free(dum);

	EXIT();
	return r;
}

static DM_RESULT
dmconfig_value2avp(GET_GRP_CONTAINER *container,
		   const struct dm_element *elem, const DM_VALUE val)
{
	ENTER();

	switch (elem->type) {
	case T_ENUM:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_ENUM;
		case AVP_ENUM:
			if (dm_avpgrp_add_string(container->ctx,
						   &container->grp, AVP_ENUM, 0,
						   VP_TRAVELPING,
						   dm_int2enum(&elem->u.e,
						   		  DM_ENUM(val)))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s (%d)]\n",
			      dm_int2enum(&elem->u.e, DM_ENUM(val)),
			      DM_ENUM(val));

			EXIT();
			return DM_OK;
		case AVP_ENUMID:
			if (dm_avpgrp_add_int32(container->ctx, &container->grp,
						  AVP_ENUMID, 0, VP_TRAVELPING,
						  DM_ENUM(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s (%d)]\n",
			      dm_int2enum(&elem->u.e, DM_ENUM(val)),
			      DM_ENUM(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_COUNTER:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_COUNTER;
		case AVP_COUNTER:
			if (dm_avpgrp_add_uint32(container->ctx, &container->grp,
						   AVP_COUNTER, 0, VP_TRAVELPING,
						   DM_UINT(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %u]\n", DM_UINT(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_INT:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_INT32;
		case AVP_INT32:
			if (dm_avpgrp_add_int32(container->ctx, &container->grp,
						  AVP_INT32, 0, VP_TRAVELPING,
						  DM_INT(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %d]\n", DM_INT(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_UINT:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_UINT32;
		case AVP_UINT32:
			if (dm_avpgrp_add_uint32(container->ctx,
						   &container->grp, AVP_UINT32, 0,
						   VP_TRAVELPING, DM_UINT(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %u]\n", DM_UINT(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_INT64:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_INT64;
		case AVP_INT64:
			if (dm_avpgrp_add_int64(container->ctx, &container->grp,
						  AVP_INT64, 0, VP_TRAVELPING,
						  DM_INT64(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %" PRIi64 "]\n", DM_INT64(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_UINT64:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_UINT64;
		case AVP_UINT64:
			if (dm_avpgrp_add_uint64(container->ctx, &container->grp,
						   AVP_UINT64, 0, VP_TRAVELPING,
						   DM_UINT64(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %" PRIu64 " ]\n", DM_UINT64(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_STR:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_STRING;
		case AVP_STRING:
			if (dm_avpgrp_add_string(container->ctx, &container->grp,
						   AVP_STRING, 0, VP_TRAVELPING,
						   DM_STRING(val) ? : "")) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: \"%s\"]\n", DM_STRING(val) ? : "");

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_BINARY:
	case T_BASE64:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_BINARY;
		case AVP_BINARY:
			if (dm_avpgrp_add_raw(container->ctx, &container->grp,
						AVP_BINARY, 0, VP_TRAVELPING,
						DM_BINARY(val) ? DM_BINARY(val)->data : "",
						DM_BINARY(val) ? DM_BINARY(val)->len : 0)) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: \"binay data....\"]\n"); /* FIXME */

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_IPADDR4:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_ADDRESS;
		case AVP_ADDRESS:
			if (dm_avpgrp_add_address(container->ctx,
						    &container->grp, AVP_ADDRESS,
						    0, VP_TRAVELPING, AF_INET,
						    DM_IP4_REF(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s]\n", inet_ntoa(DM_IP4(val)));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_BOOL:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_BOOL;
		case AVP_BOOL:
			if (dm_avpgrp_add_uint8(container->ctx, &container->grp,
						  AVP_BOOL, 0, VP_TRAVELPING,
						  (uint8_t) DM_BOOL(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s (%d)]\n",
			      DM_BOOL(val) ? "true" : "false", DM_BOOL(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_DATE:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_DATE;
		case AVP_DATE:
			if (dm_avpgrp_add_time(container->ctx, &container->grp,
						 AVP_DATE, 0, VP_TRAVELPING,
						 DM_TIME(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: (%d) %s",
			      (int)DM_TIME(val), ctime(DM_TIME_REF(val)));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_SELECTOR:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_PATH;
		case AVP_PATH: {
			char buffer[MAX_PARAM_NAME_LEN];
			char *name;

			if (!DM_SELECTOR(val))
				name = "";
			else if (!(name = dm_sel2name(*DM_SELECTOR(val),
							 buffer, sizeof(buffer)))) {
				EXIT();
				return DM_INVALID_VALUE;
			}
			if (dm_avpgrp_add_string(container->ctx, &container->grp,
						   AVP_PATH, 0,
						   VP_TRAVELPING, name)) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: \"%s\"]\n", name);

			EXIT();
			return DM_OK;
		}
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_TICKS:
		if (container->type == AVP_UNKNOWN)
			container->type = elem->flags & F_DATETIME ? AVP_ABSTICKS
								   : AVP_RELTICKS;

		switch (container->type) {
		case AVP_ABSTICKS:
		case AVP_RELTICKS: {
			ticks_t t = container->type == AVP_ABSTICKS ? ticks2realtime(DM_TICKS(val))
								    : DM_TICKS(val);

			if (dm_avpgrp_add_int64(container->ctx, &container->grp,
						  container->type, 0, VP_TRAVELPING, t)) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %" PRItick "]\n", t);

			EXIT();
			return DM_OK;
		}
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	default:
		EXIT();
		return DM_INVALID_TYPE;
	}

	/* never reached */

	EXIT();
	return DM_ERROR;
}

static DM_RESULT
dmconfig_set_cb(void *data, const dm_selector sel,
		const struct dm_element *elem,
		struct dm_value_table *base,
		const void *value __attribute__((unused)), DM_VALUE *st)
{
	SET_GRP_CONTAINER	*container = data;

	DM_VALUE		new_value;
	DM_RESULT		r;

	ENTER();

	if ((r = dmconfig_avp2value(container->header, elem, &new_value)) != DM_OK) {
		EXIT();
		return r;
	}

	if (container->session->flags & CMD_FLAG_CONFIGURE) {
		st->flags |= DV_UPDATE_PENDING;
		DM_parity_update(*st);
		cache_add(sel, "", elem, base, st, new_value, 0, NULL);
	} else {
		new_value.flags |= DV_UPDATED;
		DM_parity_update(new_value);
		r = dm_overwrite_any_value_by_selector(sel, elem->type,
							  new_value,
							  container->session->notify.slot ? : -1);
	}

	EXIT();
	return r;
}

static DM_RESULT
dmconfig_get_cb(void *data, const dm_selector sb __attribute__((unused)),
		const struct dm_element *elem, const DM_VALUE val)
{
	return elem ? dmconfig_value2avp(data, elem, val)
		    : DM_VALUE_NOT_FOUND;
}

		/* used by CMD_DB_LIST request */
static int
dmconfig_list_cb(void *data, CB_type type, dm_id id,
		 const struct dm_element *elem, const DM_VALUE value)
{
	LIST_CTX		*ctx = data;
	GET_GRP_CONTAINER	get_container = {.type = AVP_UNKNOWN};

	uint32_t		node_type;

	char			*node_name = elem->key;
	char			numbuf[UINT16_DIGITS];

	ENTER();

	if (!node_name) {
		EXIT();
		return 0;
	}

	if (ctx->firstone) {		/* hack that prevents the first element from being processed */
		ctx->firstone = 0;	/* later dm_walk_by_name might be modified or reimplemented */
		EXIT();
		return 1;
	}

	switch (type) {
	case CB_object_end:
	case CB_table_end:
	case CB_object_instance_end:
		if (ctx->level && ctx->level < ctx->max_level) {
			get_container.grp = ctx->ctx;
			get_container.ctx = talloc_parent(get_container.grp);

			if (dm_avpgrp_add_avpgrp(get_container.ctx, &get_container.grp,
						   AVP_CONTAINER, 0, VP_TRAVELPING, ctx->grp)) {
				EXIT();
				return 0;
			}
			talloc_free(ctx->grp);

			ctx->grp = get_container.ctx;
			ctx->ctx = talloc_parent(ctx->grp);

			if (dm_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER,
					   	   0, VP_TRAVELPING, get_container.grp)) {
				EXIT();
				return 0;
			}
			talloc_free(get_container.grp);
		}
		ctx->level--;

		EXIT();
		return 1;
	case CB_object_start:
		node_type = NODE_TABLE;
		ctx->level++;
		break;
	case CB_object_instance_start:
		snprintf(numbuf, sizeof(numbuf), "%hu", id);
		node_name = numbuf;
	case CB_table_start:
		node_type = NODE_OBJECT;
		ctx->level++;
		break;
	case CB_element:
		node_type = NODE_PARAMETER;
		break;
	default:
		EXIT();
		return 0;
	}

	get_container.ctx = ctx->grp;
	if (!(get_container.grp = new_dm_avpgrp(get_container.ctx))) {
		EXIT();
		return 0;
	}

	if (dm_avpgrp_add_string(get_container.ctx, &get_container.grp,
				   AVP_NODE_NAME, 0, VP_TRAVELPING, node_name)) {
		EXIT();
		return 0;
	}
	if (dm_avpgrp_add_uint32(get_container.ctx, &get_container.grp,
				   AVP_NODE_TYPE, 0, VP_TRAVELPING, node_type)) {
		EXIT();
		return 0;
	}

	switch (node_type) {
	case NODE_PARAMETER:
		if (elem->type == T_POINTER) {
			if (dm_avpgrp_add_uint32(get_container.ctx, &get_container.grp,
						   AVP_NODE_DATATYPE, 0, VP_TRAVELPING,
						   AVP_POINTER)) {
				EXIT();
				return 0;
			}
		} else if (dmconfig_value2avp(&get_container, elem, value)) {
			EXIT();
			return 0;
		}

		if (dm_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER,
					   0, VP_TRAVELPING, get_container.grp)) {
			EXIT();
			return 0;
		}
		talloc_free(get_container.grp);

		break;

	case NODE_TABLE:
	case NODE_OBJECT:
		if (ctx->level < ctx->max_level) {
			ctx->ctx = get_container.grp;
			if (!(ctx->grp = new_dm_avpgrp(ctx->ctx))) {
				EXIT();
				return 0;
			}
		} else {
			if ((node_type == NODE_OBJECT &&
			     dm_avpgrp_add_uint32(get_container.ctx, &get_container.grp,
						    AVP_NODE_SIZE, 0, VP_TRAVELPING,
						    elem->u.t.table->size)) ||
			    dm_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER,
					   	   0, VP_TRAVELPING, get_container.grp)) {
				EXIT();
				return 0;
			}
			talloc_free(get_container.grp);
		}
	}

	EXIT();
	return 1;
}

static DM_RESULT
dmconfig_retrieve_enums_cb(void *data,
			   const dm_selector sb __attribute__((unused)),
			   const struct dm_element *elem,
			   const DM_VALUE val __attribute__((unused)))
{
	OBJ_GROUP 		*obj = data;

	const struct dm_enum	*enumer;

	char			*ptr;
	int			i;

	ENTER();

	if (!elem) {
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	enumer = &elem->u.e;
	for (ptr = enumer->data, i = enumer->cnt; i; i--, ptr += strlen(ptr) + 1)
		if (dm_avpgrp_add_string(obj->req, &obj->answer_grp,
					   AVP_STRING, 0, VP_TRAVELPING, ptr)) {
			EXIT();
			return DM_OOM;
		}

	EXIT();
	return DM_OK;
}
