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
#include <event.h>
#include <syslog.h>
#include <signal.h>

#ifdef LIBDMCONFIG_DEBUG
#include "debug.h"
#endif

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "dmmsg.h"
#include "codes.h"
#include "dmconfig.h"

#include "utils/logx.h"
#include "utils/binary.h"

int dmconfig_debug_level = 1;

/** @defgroup API API
 *  This is the user visible API
 */

#define debug(format, ...)						\
	do {								\
		struct timeval tv;					\
		int _errno = errno;					\
									\
		gettimeofday(&tv, NULL);				\
		logx(LOG_DEBUG, "%ld.%06ld: %s" format, tv.tv_sec, tv.tv_usec, __FUNCTION__, ## __VA_ARGS__); \
		errno = _errno;						\
	} while (0)

static inline void postprocessRequest(COMMCONTEXT *ctx);

static void connectEvent(int fd, short event, void *arg);
static void writeEvent(int fd, short event, void *arg);
static void readEvent(int fd, short event, void *arg);

static inline int process_active_notification(DMCONTEXT *dmCtx);

		/* callbacks used by the blocking API automatically */

static void generic_connectHandler(DMCONFIG_EVENT event,
				   DMCONTEXT *dmCtx __attribute__((unused)),
				   void *userdata);
static void generic_answerHandler(DMCONFIG_EVENT event __attribute__((unused)),
				  DMCONTEXT *dmCtx __attribute__((unused)),
				  void *user_data, uint32_t answer_rc,
				  DM_AVPGRP *answer_grp);

		/* global variables */

static uint32_t hopid = 0;
static uint32_t endid = 0;

#define aux_RET(STATUS, RC) {			\
	*status = STATUS;			\
	return RC;				\
}
#define aux_RET_SIG(STATUS, RC) {		\
	sigaction(SIGPIPE, &oldaction, NULL);	\
	*status = STATUS;			\
	return RC;				\
}

#define CALLBACK(WHERE, ...) {			\
	if ((WHERE)->callback)			\
		(WHERE)->callback(__VA_ARGS__);	\
}
#define NOTIFY_CALLBACK(EVENT, GRP) {					\
	dmCtx->callbacks.active_notification.callback(EVENT, dmCtx, 	\
		dmCtx->callbacks.active_notification.user_data, GRP);	\
}

		/* communication auxiliary functions */

		/* our buffer is already a DM_REQUEST structure (ctx->buffer starts at the PACKET part)
		   we only have to set the INFO structure */
static inline void
postprocessRequest(COMMCONTEXT *ctx)
{
	ctx->req->info.avpptr = (DM_AVP *)(ctx->buffer + sizeof(DM_PACKET));
	ctx->req->info.size = dm_packet_length(&ctx->req->packet) +
							sizeof(DM_REQUEST_INFO);
}

/** @private libev write event callback */
uint32_t
event_aux_dmRead(int fd, short event, COMMCONTEXT *readCtx,
		   uint8_t *alreadyRead, COMMSTATUS *status)
{
	ssize_t		length;
	uint32_t	bufsize;
	uint32_t	len;

	if (event == EV_TIMEOUT)
		aux_RET(CONNRESET, RC_ERR_CONNECTION);

	if (event != EV_READ)	/* a number of events can be ignored */
		aux_RET(INCOMPLETE, RC_OK);

				/* nothing or not enough read -> read as much as possible */

	if (!*alreadyRead) {
		*alreadyRead = 1;

		bufsize = readCtx->cAlloc * BUFFER_CHUNK_SIZE;
		do {
					/* don't reallocate if there's still space */
			if (readCtx->bytes == bufsize) {
				readCtx->cAlloc++;
				bufsize += BUFFER_CHUNK_SIZE;

					/* allocate a DM_REQUEST structure (we're reading into the REQUEST structure) */
				if (!(readCtx->req = talloc_realloc_size(NULL, readCtx->req,
									 sizeof(DM_REQUEST_INFO) + bufsize)))
					aux_RET(ERROR, RC_ERR_ALLOC);

				readCtx->buffer = (uint8_t*)readCtx->req +
							sizeof(DM_REQUEST_INFO);
			}

			do {
				if ((length = read(fd, readCtx->buffer + readCtx->bytes,
						   bufsize - readCtx->bytes)) == -1) {
					debug(": read error: %d (%m)", errno);
					switch (errno) {
					case EWOULDBLOCK:	/* happens if data to read is multiple of BUFFER_CHUNK_SIZE */
						length = 0;
						break;
					case EINTR:
						break;
					case ETIMEDOUT:
					case ECONNRESET:
						aux_RET(CONNRESET,
							RC_ERR_CONNECTION);
					default:
						aux_RET(ERROR, RC_ERR_CONNECTION);
					}
				}
				else if (!length)
					aux_RET(CONNRESET, RC_ERR_CONNECTION);
				/* if length is nevertheless 0, there was an EWOULDBLOCK */
			} while (length == -1);	/* errno is EINTR */

			readCtx->bytes += length;
			debug(": read length: %d, total: %d (from %d)", (int)length, readCtx->bytes, bufsize);
		} while (length && readCtx->bytes == bufsize);
	} else if (readCtx->bytes >= 4 &&
		   readCtx->bytes >=
		   	(len = dm_packet_length(&readCtx->req->packet))) {

		debug(": read continue, got total: %d, req: %d", readCtx->bytes, len);

		/* foremost request was also the last one */
		if (!(readCtx->bytes - len)) {
			debug(": remove request");
			talloc_free(readCtx->req);
			readCtx->req = NULL;
			readCtx->cAlloc = readCtx->bytes = 0;
			aux_RET(NOTHING, RC_OK);
		}

		/* remove request */
		readCtx->bytes -= len;
		memmove(readCtx->buffer, readCtx->buffer + len, readCtx->bytes);
	}

			/* process read data */

						/* less than a part of one request's header to process */
	if (readCtx->bytes < 4 ||
	    readCtx->bytes < dm_packet_length(&readCtx->req->packet))
		aux_RET(INCOMPLETE, RC_OK);

	postprocessRequest(readCtx);		/* one or more requests to process */
	aux_RET(COMPLETE, RC_OK);
}

/** @private libev read event callback */
uint32_t
event_aux_dmWrite(int fd, short event, COMMCONTEXT *writeCtx,
		    COMMSTATUS *status)
{
	ssize_t			length;

	struct sigaction	action, oldaction;

	if (event == EV_TIMEOUT)
		aux_RET(CONNRESET, RC_ERR_CONNECTION);

	if (event != EV_WRITE)
		aux_RET(INCOMPLETE, RC_OK);

	if (!writeCtx->buffer) {
		writeCtx->buffer = (uint8_t *)&writeCtx->req->packet;
		writeCtx->bytes = writeCtx->req->info.size -
						sizeof(DM_REQUEST_INFO);
	}

	memset(&action, 0, sizeof(struct sigaction));
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, &oldaction);

	do {
		if ((length = write(fd, writeCtx->buffer,
				    writeCtx->bytes)) == -1)
			switch (errno) {
			case EAGAIN:	/* can only happen when it tries to write the second request in one write event */
				aux_RET_SIG(NOTHING, RC_OK);
			case EPIPE:
			case ECONNRESET:
				aux_RET_SIG(CONNRESET, RC_ERR_CONNECTION);
			case EINTR:
				break;
			default:
				aux_RET_SIG(ERROR, RC_ERR_CONNECTION);
			}
		else if (!length)
			aux_RET_SIG(CONNRESET, RC_ERR_CONNECTION);
	} while (length == -1);	/* errno is EINTR */

	writeCtx->buffer += length;
	writeCtx->bytes -= length;

	aux_RET_SIG((writeCtx->bytes ? INCOMPLETE : COMPLETE), RC_OK);
}

/** @private free all requests in a DMCONTEXT */
void
dm_free_requests(DMCONTEXT *dmCtx)
{
	talloc_free(dmCtx->requestlist_head);
	dmCtx->requestlist_head = NULL;

	if (event_pending(&dmCtx->writeCtx.event, EV_WRITE | EV_PERSIST, NULL))
		event_del(&dmCtx->writeCtx.event);
	if (event_pending(&dmCtx->readCtx.event, EV_READ | EV_PERSIST, NULL))
		event_del(&dmCtx->readCtx.event);

	dmCtx->writeCtx.buffer = NULL;
	if (dmCtx->readCtx.req) {
		talloc_free(dmCtx->readCtx.req);
		dmCtx->readCtx.req = NULL;
		dmCtx->readCtx.cAlloc = dmCtx->readCtx.bytes = 0;
	}
}

		/* callback register functions */

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
dm_register_connect_callback(DMCONTEXT *dmCtx, int type,
			     DMCONFIG_CONNECT_CALLBACK callback, void *userdata)
{
	CONNEVENTCTX		*ctx;
	struct timeval		timeout;

	int			fd = dm_context_get_socket(dmCtx);
	int			flags;

	struct sockaddr_un	sockaddr_un;
	struct sockaddr_in	sockaddr_in;

	struct sockaddr		*sockaddr;
	socklen_t		sockaddr_len;

	if ((flags = fcntl(fd, F_GETFL)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK))
		return RC_ERR_CONNECTION;

	if (type == AF_UNIX) {
		memset(&sockaddr_un, 0, sizeof(sockaddr_un));

		sockaddr_un.sun_family = AF_UNIX;
		strncpy(sockaddr_un.sun_path + 1, SERVER_LOCAL,
			sizeof(sockaddr_un.sun_path) - 1);

		sockaddr = (struct sockaddr*)&sockaddr_un;
		sockaddr_len = sizeof(sockaddr_un);
	} else { /* AF_INET */
		memset(&sockaddr_in, 0, sizeof(sockaddr_in));

		sockaddr_in.sin_family = AF_INET;
		sockaddr_in.sin_port = htons(SERVER_PORT);
		sockaddr_in.sin_addr.s_addr = htonl(SERVER_IP);

		sockaddr = (struct sockaddr*)&sockaddr_in;
		sockaddr_len = sizeof(sockaddr_in);
	}

	while (connect(fd, sockaddr, sockaddr_len) == -1)
		if (errno == EINPROGRESS)
			break;
		else if (errno == EAGAIN)
			continue;
		else
			return RC_ERR_CONNECTION;

	if (!(ctx = talloc(NULL, CONNEVENTCTX)))
		return RC_ERR_ALLOC;

	ctx->callback = callback;
	ctx->user_data = userdata;
	ctx->dmCtx = dmCtx;

	event_set(&ctx->event, fd, EV_WRITE, connectEvent, ctx);
	event_base_set(dm_context_get_event_base(dmCtx), &ctx->event);

	timeout.tv_sec = TIMEOUT_WRITE_REQUESTS;	/* if the connect was already successful, there should be no delay */
	timeout.tv_usec = 0;

	if (event_add(&ctx->event, &timeout)) {
		talloc_free(ctx);
		return RC_ERR_ALLOC;
	}

	return RC_OK;
}

/** send an asynchonous request with a list of arguments
 *
 * Start an asynchonous request and invoke a callback when the operation
 * completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] grp         Pointer to request arguments
 * @param [in] callback    Callback function to invoke
 * @param [in] callback_ud Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_register_request(DMCONTEXT *dmCtx, uint32_t code, DM_AVPGRP *grp,
			    DMCONFIG_CALLBACK callback, void *callback_ud)
{
	DM_AVPGRP	*completegrp;

	REQUESTINFO	*new, *cur;

	struct timeval	timeout;

	switch (hopid) {		/* one never knows... */
	case 0:		srand((unsigned int)time(NULL));
	case MAX_INT:	hopid = endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
			break;
	default:	hopid = ++endid;
	}

	if (!dmCtx->requestlist_head) {
		if (!(dmCtx->requestlist_head = talloc(NULL, REQUESTINFO)))
			return RC_ERR_ALLOC;
		memset(dmCtx->requestlist_head, 0, sizeof(REQUESTINFO));
	}
	if (!(new = talloc(dmCtx->requestlist_head, REQUESTINFO))) {
		talloc_free(dmCtx->requestlist_head);
		return RC_ERR_ALLOC;
	}

	if (!(new->request = new_dm_request(new, code, CMD_FLAG_REQUEST,
					      APP_ID, hopid, endid))) {
		talloc_free(dmCtx->requestlist_head);
		return RC_ERR_ALLOC;
	}

	if (!(completegrp = new_dm_avpgrp(new->request)) ||
	    dm_avpgrp_add_uint32(new->request, &completegrp, AVP_SESSIONID, 0,
				   VP_TRAVELPING, dmCtx->sessionid) ||
	    (grp && dm_avpgrp_add_avpgrp(new->request, &completegrp,
	    				   AVP_CONTAINER, 0, VP_TRAVELPING,
					   grp)) ||
	    build_dm_request(new, &new->request, completegrp)) {
		talloc_free(dmCtx->requestlist_head);
		return RC_ERR_ALLOC;
	}
	talloc_free(completegrp);

#ifdef LIBDMCONFIG_DEBUG
	if (dmconfig_debug_level) {
		fprintf(stderr, "Send request:\n");
		dump_dm_packet(new->request);
	}
#endif

	new->callback = callback;
	new->user_data = callback_ud;
	new->dmCtx = dmCtx;
	new->status = REQUEST_SHALL_WRITE;
	new->code = code;
	new->hopid = hopid;
	new->next = NULL;

	for (cur = dmCtx->requestlist_head; cur->next; cur = cur->next);
	cur->next = new;

	if (!event_pending(&dmCtx->writeCtx.event, EV_WRITE | EV_PERSIST, NULL)) {
		event_set(&dmCtx->writeCtx.event, dmCtx->socket,
			  EV_WRITE | EV_PERSIST, writeEvent, dmCtx);
		event_base_set(dm_context_get_event_base(dmCtx), &dmCtx->writeCtx.event);

		timeout.tv_sec = TIMEOUT_WRITE_REQUESTS;
		timeout.tv_usec = 0;

		if (event_add(&dmCtx->writeCtx.event, &timeout)) {
			talloc_free(dmCtx->requestlist_head);
			return RC_ERR_ALLOC;
		}
	}

	return RC_OK;
}

/** send an compound asynchonous request, first argument is a boolean
 *
 * Start an asynchonous request where the first argument is a boolean,
 * invoke a callback when the operation completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] bool        First request argument, must be a boolean
 * @param [in] grp         Pointer to more request arguments
 * @param [in] callback    Callback function to invoke
 * @param [in] callback_ud Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_register_request_bool_grp(DMCONTEXT *dmCtx, uint32_t code,
				     uint8_t bool, DM_AVPGRP *grp,
				     DMCONFIG_CALLBACK callback,
				     void *callback_ud)
{
	DM_AVPGRP	*new;
	uint32_t	rc;

	if (!(new = dm_grp_new()) ||
	    dm_avpgrp_add_uint8(NULL, &new, AVP_BOOL, 0, VP_TRAVELPING, bool) ||
	    dm_avpgrp_add_avpgrp(NULL, &new, AVP_CONTAINER, 0,
	    			   VP_TRAVELPING, grp)) {
		dm_grp_free(new);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, code, new, callback,
					 callback_ud);

	dm_grp_free(new);
	return rc;
}

/** send an compound asynchonous request, consisting of an uint32 and two timeouts
 *
 * Start an asynchonous request where the first argument an uint32 followed by two timeouts,
 * invoke a callback when the operation completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] val         First request argument, must be UInt32
 * @param [in] timeval1    Second request argument, must be a struct timeval
 * @param [in] timeval2    Third request argument, must be a struct timeval
 * @param [in] callback    Callback function to invoke
 * @param [in] callback_ud Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_register_request_uint32_timeouts(DMCONTEXT *dmCtx, uint32_t code,
					    uint32_t val, struct timeval *timeval1,
					    struct timeval *timeval2,
					    DMCONFIG_CALLBACK callback,
					    void *callback_ud)
{
	DM_AVPGRP	*grp;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, val) ||
	    (timeval1 &&
	     dm_avpgrp_add_timeval(NULL, &grp, AVP_TIMEOUT_SESSION, 0,
	     			     VP_TRAVELPING, *timeval1)) ||
	    (timeval2 &&
	     dm_avpgrp_add_timeval(NULL, &grp, AVP_TIMEOUT_REQUEST, 0,
	     			     VP_TRAVELPING, *timeval2))) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, code, grp, callback,
					 callback_ud);

	dm_grp_free(grp);
	return rc;
}

/** send an compound asynchonous request, only argument is a string
 *
 * Start an asynchonous request where the only argument is a string,
 * invoke a callback when the operation completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] str         Request argument, must be a string
 * @param [in] callback    Callback function to invoke
 * @param [in] callback_ud Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_register_request_string(DMCONTEXT *dmCtx, uint32_t code,
				   const char *str, DMCONFIG_CALLBACK callback,
				   void *callback_ud)
{
	DM_AVPGRP	*grp;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_STRING, 0,
				   VP_TRAVELPING, str)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, code, grp, callback, callback_ud);

	dm_grp_free(grp);
	return rc;
}

/** send an compound asynchonous request, only argument is a data-model path
 *
 * Start an asynchonous request where the only argument is a data-model path,
 * invoke a callback when the operation completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] path        Request argument, must be a valid data-model path
 * @param [in] callback    Callback function to invoke
 * @param [in] callback_ud Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_register_request_path(DMCONTEXT *dmCtx, uint32_t code,
				 const char *path, DMCONFIG_CALLBACK callback,
				 void *callback_ud)
{
	DM_AVPGRP	*grp;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_PATH, 0,
				   VP_TRAVELPING, path)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, code, grp, callback, callback_ud);

	dm_grp_free(grp);
	return rc;
}

/** send an compound asynchonous request, only argument is a IP(v4) address
 *
 * Start an asynchonous request where the only argument is a IP(v4) address
 * invoke a callback when the operation completes (either with success or error)
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] addr        Request argument, must be a IP(v4) address
 * @param [in] callback    Callback function to invoke
 * @param [in] callback_ud Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Callback was installed
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @TODO: extend to IPv6
 * @ingroup API
 */
uint32_t
dm_generic_register_request_char_address(DMCONTEXT *dmCtx, uint32_t code,
					 const char *str, struct in_addr addr,
					 DMCONFIG_CALLBACK callback,
					 void *callback_ud)
{
	DM_AVPGRP	*grp;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_STRING, 0,
				   VP_TRAVELPING, str) ||
	    dm_avpgrp_add_address(NULL, &grp, AVP_ADDRESS, 0, VP_TRAVELPING,
	    			    AF_INET, &addr)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, code, grp, callback, callback_ud);

	dm_grp_free(grp);
	return rc;
}

		/* generic connection / send request functions (blocking API) */

/** create a new DM socket in a given context
 *
 * Create a new blocking socket in a context with default settings
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] type        Type of socket (AF_INET or AF_UNIX)
 *
 * @retval RC_OK                Socket created
 * @retval RC_ERR_MISC          Something unexpected happened
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_init_socket(DMCONTEXT *dmCtx, int type)
{
	uint32_t rc;

	if ((rc = dm_create_socket(dmCtx, type)))
		return rc;

	ev_now_update(dm_context_get_ev_loop(dmCtx));	/* workaround for libev time update problem
							   otherwise ev_now() time is updated only at ev_loop */

	if ((rc = dm_register_connect_callback(dmCtx, type,
					       generic_connectHandler, &rc)))
		return rc;

	if (event_base_dispatch(dm_context_get_event_base(dmCtx)) == -1)
		return RC_ERR_MISC;

	return rc;
}

/** @private default, blocking connect handler
 *
 * return only a code
 */
static void
generic_connectHandler(DMCONFIG_EVENT event,
		       DMCONTEXT *dmCtx __attribute__((unused)), void *userdata)
{
	uint32_t *rc = userdata;

	*rc = event == DMCONFIG_ERROR_CONNECTING ? RC_ERR_CONNECTION : RC_OK;
}


/** Synchonous request with a list of arguments
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] grp         Pointer to request arguments
 * @param [inout] ret      Pointer to pointer to put the result into
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_send_request(DMCONTEXT *dmCtx, uint32_t code, DM_AVPGRP *grp,
			DM_AVPGRP **ret)
{
	struct _result {
		uint32_t	rc;
		DM_AVPGRP	*grp;
		DM_AVPGRP	**ret;
	} result;
	uint32_t rc;

	ev_now_update(dm_context_get_ev_loop(dmCtx));	/* workaround for libev time update problem
							   otherwise ev_now() time is updated only at ev_loop */

	if ((rc = dm_generic_register_request(dmCtx, code, grp,
					      generic_answerHandler, &result)))
		return rc;

	result.rc = RC_ERR_CONNECTION;
	result.grp = grp;
	result.ret = ret;

	return event_base_dispatch(dm_context_get_event_base(dmCtx)) == -1 ?
							RC_ERR_MISC : result.rc;
}


/** Synchonous compound request, first argument is a boolean
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] bool        First request argument, must be a boolean
 * @param [in] grp         Pointer to more request arguments
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_send_request_bool_grp(DMCONTEXT *dmCtx, uint32_t code, uint8_t bool,
				 DM_AVPGRP *grp)
{
	DM_AVPGRP	*new;
	uint32_t	rc;

	if (!(new = dm_grp_new()) ||
	    dm_avpgrp_add_uint8(NULL, &new, AVP_BOOL, 0, VP_TRAVELPING, bool) ||
	    dm_avpgrp_add_avpgrp(NULL, &new, AVP_CONTAINER, 0,
	    			   VP_TRAVELPING, grp)) {
		dm_grp_free(new);
		return RC_ERR_ALLOC;
	}
	rc = dm_generic_send_request(dmCtx, code, new, NULL);

	dm_grp_free(new);
	return rc;
}

/** Synchonous compound request, consisting of an uint32 and two timeouts
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] val         First request argument, must be UInt32
 * @param [in] timeval1    Second request argument, must be a struct timeval
 * @param [in] timeval2    Third request argument, must be a struct timeval
 * @param [inout] ret      Pointer to pointer to put the result into
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_send_request_uint32_timeouts_get_grp(DMCONTEXT *dmCtx, uint32_t code,
						uint32_t val,
						struct timeval *timeval1,
						struct timeval *timeval2,
						DM_AVPGRP **ret)
{
	uint32_t	rc;
	DM_AVPGRP	*grp;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, val) ||
	    (timeval1 &&
	     dm_avpgrp_add_timeval(NULL, &grp, AVP_TIMEOUT_SESSION, 0,
	     			     VP_TRAVELPING, *timeval1)) ||
	    (timeval2 &&
	     dm_avpgrp_add_timeval(NULL, &grp, AVP_TIMEOUT_REQUEST, 0,
	     			     VP_TRAVELPING, *timeval2))) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	if ((rc = dm_generic_send_request(dmCtx, code, grp, ret))) {
		dm_grp_free(grp);
		return rc;
	}

	if (ret)
		talloc_steal(NULL, *ret);
	dm_grp_free(grp);

	return RC_OK;
}

/** Synchonous compound request, only argument is a string
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] str         Request argument, must be a string
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_send_request_string(DMCONTEXT *dmCtx, uint32_t code, const char *str)
{
	DM_AVPGRP	*grp;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_STRING, 0, VP_TRAVELPING, str)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_send_request(dmCtx, code, grp, NULL);

	dm_grp_free(grp);
	return rc;
}

/** Synchonous compound request, only argument is a data-model path
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] path        Request argument, must be a valid data-model path
 * @param [inout] answer   Pointer to pointer to put the result into
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_send_request_path_get_grp(DMCONTEXT *dmCtx, uint32_t code,
				     const char *path, DM_AVPGRP **answer)
{
	DM_AVPGRP	*grp;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, path)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}
	if ((rc = dm_generic_send_request(dmCtx, code, grp, answer))) {
		dm_grp_free(grp);
		return rc;
	}

	if (answer)
		talloc_steal(NULL, *answer);
	dm_grp_free(grp);

	return RC_OK;
}

/** Synchonous compound request, only argument is a data-model path, return value is a single string
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] path        Request argument, must be a valid data-model path
 * @param [inout] data     Pointer to char pointer to put the result string into
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_generic_send_request_path_get_char(DMCONTEXT *dmCtx, uint32_t code,
				      const char *path, char **data)
{
	DM_AVPGRP	*ret;
	uint32_t	rc;

	if ((rc = dm_generic_send_request_path_get_grp(dmCtx, code, path, &ret)))
		return rc;
	rc = dm_decode_string(ret, data);
	dm_grp_free(ret);
	return rc;
}

/** Synchonous compound request, arguments are a string and an IP(v4) address
 *
 * @param [in] dmCtx       Pointer to socket context to work on
 * @param [in] code        Request code
 * @param [in] str         First request argument, must be a string
 * @param [in] addr        Second request argument, must be an IP(v4) address
 * @param [inout] data     Pointer to char pointer to put the result string into
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @TODO: extend to IPv6
 * @ingroup API
 */
uint32_t
dm_generic_send_request_char_address_get_char(DMCONTEXT *dmCtx, uint32_t code,
					      const char *str,
					      struct in_addr addr, char **data)
{
	DM_AVPGRP	*grp;
	DM_AVPGRP	*answer;
	uint32_t	rc;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_STRING, 0, VP_TRAVELPING, str) ||
	    dm_avpgrp_add_address(NULL, &grp, AVP_ADDRESS, 0, VP_TRAVELPING,
	    			    AF_INET, &addr)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}
	if ((rc = dm_generic_send_request(dmCtx, code, grp, &answer))) {
		dm_grp_free(grp);
		return rc;
	}
	rc = dm_decode_string(answer, data);
	dm_grp_free(grp);
	return rc;
}

/** @private default, blocking answer handler
 */
static void
generic_answerHandler(DMCONFIG_EVENT event __attribute__((unused)),
		      DMCONTEXT *dmCtx __attribute__((unused)), void *user_data,
		      uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
	struct _result {
		uint32_t	rc;
		DM_AVPGRP	*grp;
		DM_AVPGRP	**ret;
	} *result = user_data;

	if ((result->rc = answer_rc))
		return;

	if (result->ret) {
		if (answer_grp)
			talloc_steal(result->grp, answer_grp);
		*result->ret = answer_grp;
	}
}

		/* auxiliary event handler */

/** @private default connect event handler,
 *           translate from libev to connect callback
 */
static void
connectEvent(int fd, short event, void *arg)
{
	CONNEVENTCTX	*ctx = arg;
	int		rc;
	socklen_t	size = sizeof(rc);

	if (fd != -1 &&
	    (event != EV_WRITE ||
	     getsockopt(fd, SOL_SOCKET, SO_ERROR, &rc, &size) ||
	     size != sizeof(rc) || rc)) {
	    	CALLBACK(ctx, DMCONFIG_ERROR_CONNECTING, ctx->dmCtx,
			 ctx->user_data);
	} else
		CALLBACK(ctx, DMCONFIG_CONNECTED, ctx->dmCtx, ctx->user_data);

	talloc_free(ctx);
}

/** @private libev write event handler,
 */
static void
writeEvent(int fd, short event, void *arg)
{
	DMCONTEXT	*dmCtx = arg;
	COMMCONTEXT	*ctx = &dmCtx->writeCtx;

	COMMSTATUS	status;
	uint32_t	rc;

	struct timeval	timeout;

	do {
		if (!ctx->buffer) {
			for (ctx->cur_request = dmCtx->requestlist_head->next;
			     ctx->cur_request &&
			     ctx->cur_request->status != REQUEST_SHALL_WRITE;
			     ctx->cur_request = ctx->cur_request->next);
			if (!ctx->cur_request) {	/* all requests written */
				event_del(&ctx->event);
				return;
			}
			ctx->cur_request->status = REQUEST_WRITING;
			ctx->req = ctx->cur_request->request;
		}

		rc = event_aux_dmWrite(fd, event, ctx, &status);
		switch (status) {
		case COMPLETE:
			talloc_free(ctx->cur_request->request);
			ctx->buffer = NULL;

			ctx->cur_request->status = REQUEST_SHALL_READ;

			if (!event_pending(&dmCtx->readCtx.event,
					   EV_READ | EV_PERSIST, NULL)) {
				event_set(&dmCtx->readCtx.event, dmCtx->socket,
					  EV_READ | EV_PERSIST, readEvent, dmCtx);
				event_base_set(dm_context_get_event_base(dmCtx),
					       &dmCtx->readCtx.event);

				timeout.tv_sec = TIMEOUT_READ_REQUESTS;
				timeout.tv_usec = 0;

				if (event_add(&dmCtx->readCtx.event, &timeout)) {
					rc = RC_ERR_ALLOC;
					break;
				}
			}

			timeout.tv_sec = TIMEOUT_WRITE_REQUESTS;
			timeout.tv_usec = 0;

			if (event_add(&ctx->event, &timeout))	/* increase writeEvent's timeout */
				rc = RC_ERR_ALLOC;

			break;
		case INCOMPLETE:
			timeout.tv_sec = TIMEOUT_CHUNKS;
			timeout.tv_usec = 0;

			if (event_add(&ctx->event, &timeout)) {	/* reduce writeEvent's timeout */
				rc = RC_ERR_ALLOC;
				break;
			}
		case NOTHING:
			return;
		default:	/* CONNRESET or ERROR */
			break;
		}
	} while (!rc);

	CALLBACK(ctx->cur_request, DMCONFIG_ERROR_WRITING,
		 ctx->cur_request->dmCtx, ctx->cur_request->user_data, rc, NULL);

	L_FOREACH(REQUESTINFO, cur, dmCtx->requestlist_head)
		if (cur->status != REQUEST_SHALL_READ)
			talloc_free(cur->request);
	talloc_free(dmCtx->requestlist_head);
	dmCtx->requestlist_head = NULL;

	ctx->cur_request = NULL;
	ctx->req = NULL;
	ctx->buffer = NULL;
	event_del(&ctx->event);

	talloc_free(dmCtx->readCtx.req);
	dmCtx->readCtx.req = NULL;

	if (event_pending(&dmCtx->readCtx.event, EV_READ | EV_PERSIST, NULL))
		event_del(&dmCtx->readCtx.event);
}

/** @private libev read event handler,
 */
static void
readEvent(int fd, short event, void *arg)
{
	DMCONTEXT	*dmCtx = arg;
	COMMCONTEXT	*ctx = &dmCtx->readCtx;

	uint32_t	avpcode;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	uint8_t		alreadyRead = 0;

	struct timeval	timeout;

	for (;;) {
		uint32_t	hopid;
		REQUESTINFO	*cur, *reqEl;

		COMMSTATUS	status;
		uint32_t	rc;

		rc = event_aux_dmRead(fd, event, ctx, &alreadyRead, &status);
		switch (status) {
		case INCOMPLETE:
			timeout.tv_sec = TIMEOUT_CHUNKS;
			timeout.tv_usec = 0;

			if (event_add(&ctx->event, &timeout))	/* reduce readEvent's timeout */
				goto abort;
		case NOTHING:
			return;
		case COMPLETE:
			break;
		default:	/* CONNRESET or ERROR */
			goto abort;
		}

#ifdef LIBDMCONFIG_DEBUG
		if (dmconfig_debug_level) {
			fprintf(stderr, "Recieved %s:\n",
				dm_packet_flags(&ctx->req->packet) &
					CMD_FLAG_REQUEST ? "request" : "answer");
			dump_dm_packet(ctx->req);
			dm_request_reset_avp(ctx->req);
		}
#endif

					/* server request */
		if (dm_packet_flags(&ctx->req->packet) & CMD_FLAG_REQUEST) {
			switch (dm_packet_code(&ctx->req->packet)) {

			default:
				goto abort;
			}
		} else {
			if (!dmCtx->requestlist_head || !dmCtx->requestlist_head->next)
				goto abort;

			hopid = dm_hop2hop_id(&ctx->req->packet);

			for (cur = dmCtx->requestlist_head;
			     cur->next && cur->next->hopid != hopid;
			     cur = cur->next);
			if (!cur->next || cur->next->status != REQUEST_SHALL_READ)
				goto abort;
			reqEl = cur->next;
			cur->next = reqEl->next;

			if (dm_request_get_avp(ctx->req, &avpcode, &flags,
						 &vendor_id, &data, &len) ||
			    avpcode != AVP_RC || len != sizeof(uint32_t)) {
				CALLBACK(reqEl, DMCONFIG_ERROR_READING, reqEl->dmCtx, reqEl->user_data, RC_ERR_MISC, NULL);
				goto cleanup;
			}

			if ((rc = dm_get_uint32_avp(data))) {
				CALLBACK(reqEl, DMCONFIG_ANSWER_READY, reqEl->dmCtx, reqEl->user_data, rc, NULL);

						/* clean up callback structures if necessary, so the read event is deleted */
				switch (reqEl->code) {
				case CMD_SUBSCRIBE_NOTIFY:
					memset(&dmCtx->callbacks.active_notification, 0,
					       sizeof(ACTIVE_NOTIFY_INFO));
					break;
				}

				goto cleanup;
			} else /* RC_OK */ {
				switch (reqEl->code) {
				case CMD_UNSUBSCRIBE_NOTIFY:
					memset(&dmCtx->callbacks.active_notification, 0,
					       sizeof(ACTIVE_NOTIFY_INFO));
					break;

				case CMD_ENDSESSION:	/*
							 * allows the implicit abortion (deletion of read event -> event loop returns) of
							 * asynchronous processes (ping, active notify, etc)
							 */
					memset(&dmCtx->callbacks, 0,
					       sizeof(struct _dmContext_callbacks));
					break;
				}
			}

			if (dm_request_get_avp(ctx->req, &avpcode, &flags, &vendor_id, &data, &len)) {
				CALLBACK(reqEl, DMCONFIG_ANSWER_READY, reqEl->dmCtx, reqEl->user_data, RC_OK, NULL);
			} else if (avpcode == AVP_CONTAINER) {
				DM_AVPGRP *answer;

				if ((answer = dm_decode_avpgrp(ctx->req, data, len))) {
					CALLBACK(reqEl, DMCONFIG_ANSWER_READY, reqEl->dmCtx, reqEl->user_data, RC_OK, answer);
				} else {
					CALLBACK(reqEl, DMCONFIG_ERROR_READING, reqEl->dmCtx, reqEl->user_data, RC_ERR_ALLOC, NULL);
				}
			} else {
				CALLBACK(reqEl, DMCONFIG_ERROR_READING, reqEl->dmCtx, reqEl->user_data, RC_ERR_MISC, NULL);
			}

cleanup:

			if (dmCtx->requestlist_head->next)
				talloc_free(reqEl);
			else {
				talloc_free(dmCtx->requestlist_head);
				dmCtx->requestlist_head = NULL;
			}
		}

		for (cur = dmCtx->requestlist_head;
		     cur && cur->status != REQUEST_SHALL_READ;
		     cur = cur->next);
		if (!cur &&						/* nothing more to read (at least not expected) */
		    !dmCtx->callbacks.active_notification.callback) {	/* FIXME: a reference counter would be cleaner */
			event_del(&ctx->event);
				/* if there's nothing more to read, the fields are reset and NOTHING is returned */
			event_aux_dmRead(fd, EV_READ, ctx,
					   &alreadyRead, &status);
			if (status != NOTHING)
				goto abort;

			return;
		}

		timeout.tv_sec = TIMEOUT_READ_REQUESTS;
		timeout.tv_usec = 0;

		if (event_add(&ctx->event, &timeout))	/* increase readEvent's timeout */
			break;
	}

abort:

	event_del(&ctx->event);
	talloc_free(ctx->req);
	ctx->req = NULL;
	ctx->cAlloc = ctx->bytes = 0;
	memset(&dmCtx->callbacks, 0, sizeof(struct _dmContext_callbacks));
}

/** @private process notification events,
 *           invoke notify callback
 */
static inline int
process_active_notification(DMCONTEXT *dmCtx)
{
	COMMCONTEXT	*ctx = &dmCtx->readCtx;

	uint32_t	avpcode;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	DM_AVPGRP	*notify;

	if (!dmCtx->callbacks.active_notification.callback)
		return -1;

	if (dm_request_get_avp(ctx->req, &avpcode, &flags, &vendor_id, &data, &len) ||
	    avpcode != AVP_CONTAINER || !len ||
	    !(notify = dm_decode_avpgrp(ctx->req, data, len))) {
		NOTIFY_CALLBACK(DMCONFIG_ERROR_READING, NULL);
	} else {
		NOTIFY_CALLBACK(DMCONFIG_ANSWER_READY, notify);
	}

	return 0;
}

		/* enduser API (both blocking and nonblocking) */

/** build AVP group for SET packet
 *
 * @param [inout] grp     Pointer to a DM_AVPGRP pointer to put the result into
 * @param [in] name       Name (path) of config parameter to set
 * @param [in] type       Type of config parameter to set
 * @param [in] value      Pointer to value to set
 * @param [in] size       Length of value
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_grp_set(DM_AVPGRP **grp, const char *name, int type,
	   void *value, size_t size)
{
	DM_AVPGRP *pair;

	if (!(pair = new_dm_avpgrp(*grp)) ||
	    dm_avpgrp_add_string(*grp, &pair, AVP_PATH, 0, VP_TRAVELPING, name) ||
	    dm_avpgrp_add_raw(*grp, &pair, type, 0, VP_TRAVELPING, value, size) ||
	    dm_avpgrp_add_avpgrp(NULL, grp, AVP_CONTAINER, 0,
	    			   VP_TRAVELPING, pair)) {
		dm_grp_free(pair);
		return RC_ERR_ALLOC;
	}

	dm_grp_free(pair);
	return RC_OK;
}

/** Synchonous add instance request
 *
 * Add a new instance of the given object, the path argument must refer to a valid
 * multi instance object
 *
 * @param [in] dmCtx            Pointer to socket context to work on
 * @param [in] path             Path of the object to instanciate, must be a valid data-model path
 * @param [inout] instance      Pointer to an UInt16 to put the create instance Id into
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_send_add_instance(DMCONTEXT *dmCtx, const char *path, uint16_t *instance)
{
	uint32_t	rc;
	DM_AVPGRP	*grp;
	DM_AVPGRP	*answer;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, path) ||
	    dm_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, *instance)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}
	if ((rc = dm_generic_send_request(dmCtx, CMD_DB_ADDINSTANCE, grp, &answer))) {
		dm_grp_free(grp);
		return rc;
	}

	rc = dm_decode_add_instance(answer, instance);
	dm_grp_free(grp);
	return rc;
}

/** Synchonous list request
 *
 * List a values under a give path up to a given depth
 *
 * @param [in] dmCtx            Pointer to socket context to work on
 * @param [in] name             Path to start the list at, must be a valid data-model path
 * @param [in] level            Number of level to recurse into
 * @param [inout] answer        Pointer to an pointer to put the resuling DM_AVPGRP pointer into,
 *                              caller has to free the answer afterwards
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_send_list(DMCONTEXT *dmCtx, const char *name, uint16_t level,
	     DM_AVPGRP **answer)
{
	uint32_t	rc;
	DM_AVPGRP	*grp;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, level) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, name)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	if (!(rc = dm_generic_send_request(dmCtx, CMD_DB_LIST, grp, answer)))
		talloc_steal(NULL, *answer);
	dm_grp_free(grp);
	return rc;
}

		/* register requests (nonblocking API) */

/** Initialize a subscription to active notification
 * 
 * Initialize a subscribtion to active notification and install a notify callback for them.
 * This is an asynchronous operation, on completion a callback will be invoked
 *
 * @param [in] dmCtx               Pointer to socket context to work on
 * @param [in] notify_callback     Notification callback to install
 * @param [in] notify_callback_ud  Pointer to userdata that will be passed to the notification callback funtion
 * @param [in] callback            Callback function to invoke on completion
 * @param [in] callback_ud         Pointer to userdata that will be passed to the callback funtions

 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_register_subscribe_notify(DMCONTEXT *dmCtx,
			     DMCONFIG_ACTIVE_NOTIFY notify_callback,
			     void *notify_callback_ud,
			     DMCONFIG_CALLBACK callback,
			     void *callback_ud)
{
	uint32_t rc;

	if ((rc = dm_generic_register_request(dmCtx, CMD_SUBSCRIBE_NOTIFY, NULL,
					      callback, callback_ud)))
		return rc;

	dmCtx->callbacks.active_notification.callback = notify_callback;
	dmCtx->callbacks.active_notification.user_data = notify_callback_ud;

	return RC_OK;
}

/** Asynchonous add an object instance
 * 
 * Add a new instance of the given object, the path argument must refer to a valid
 * multi instance object, invoke callback on completion
 *
 * @param [in] dmCtx            Pointer to socket context to work on
 * @param [in] path             Path of the object to instanciate, must be a valid data-model path
 * @param [inout] instance      Pointer to an UInt16 to put the create instance Id into
 * @param [in] callback         Callback function to invoke on completion
 * @param [in] callback_ud      Pointer to userdata that will be passed to the callback funtions
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_register_add_instance(DMCONTEXT *dmCtx, const char *path, uint16_t instance,
			 DMCONFIG_CALLBACK callback, void *callback_ud)
{
	uint32_t	rc;
	DM_AVPGRP	*grp;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, path) ||
	    dm_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, instance)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, CMD_DB_ADDINSTANCE, grp, callback, callback_ud);
	dm_grp_free(grp);
	return rc;
}

/** Asynchonous list request
 *
 * List a values under a give path up to a given depth,
 * invoke callback on completion
 *
 * @param [in] dmCtx            Pointer to socket context to work on
 * @param [in] name             Path to start the list at, must be a valid data-model path
 * @param [in] level            Number of level to recurse into
 * @param [in] callback         Callback function to invoke on completion
 * @param [in] callback_ud      Pointer to userdata that will be passed to the callback funtions
 *                              caller has to free the answer afterwards
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_register_list(DMCONTEXT *dmCtx, const char *name, uint16_t level,
		 DMCONFIG_CALLBACK callback, void *callback_ud)
{
	uint32_t	rc;
	DM_AVPGRP	*grp;

	if (!(grp = dm_grp_new()) ||
	    dm_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, level) ||
	    dm_avpgrp_add_string(NULL, &grp, AVP_PATH, 0, VP_TRAVELPING, name)) {
		dm_grp_free(grp);
		return RC_ERR_ALLOC;
	}

	rc = dm_generic_register_request(dmCtx, CMD_DB_LIST, grp, callback, callback_ud);
	dm_grp_free(grp);
	return rc;
}

/** process AVP group returned by dm_send|register_get_passive_notifications or
 *  received as an active notification callback parameter
 *
 * @param [in] grp              DM_AVPGRP to decode
 * @param [inout] type          Pointer to store type of notification
 * @param [inout] notify        Pointer to an pointer to put the resuling DM_AVPGRP pointer into,
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_decode_notifications(DM_AVPGRP *grp, uint32_t *type, DM_AVPGRP **notify)
{
	DM_AVPGRP	*ev_container;

	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	if (dm_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len)) {
		*type = NOTIFY_NOTHING;	/* special notify type - queue was empty */
		if (notify)
			*notify = NULL;
		return RC_OK;
	}
	if (code != AVP_CONTAINER || !len)
		return RC_ERR_MISC;

	if (!(ev_container = dm_decode_avpgrp(grp, data, len)))
		return RC_ERR_ALLOC;

	if (dm_avpgrp_get_avp(ev_container, &code, &flags, &vendor_id,
				&data, &len) ||
	    code != AVP_NOTIFY_TYPE || len != sizeof(uint32_t)) {
		dm_grp_free(ev_container);
		return RC_ERR_MISC;
	}
	*type = dm_get_uint32_avp(data);

	if (notify)
		*notify = ev_container;
	else
		dm_grp_free(ev_container);

	return RC_OK;
}

/** converts an arbitrary typed AVP data to an ASCII string
 *
 * @param [in] type       Type of AVP to decode
 * @param [in] data       Pointer to date to decode
 * @param [in] len        Length of value
 * @param [inout] val     Pointer to pointer to store the result in
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_decode_unknown_as_string(uint32_t type, void *data, size_t len, char **val)
{
	int		af;
	union {
		struct in_addr	in;
		struct in6_addr	in6;
	} addr;
	char *dum;

	switch (type) {
	case AVP_BOOL:
		return (*val = strdup(dm_get_uint8_avp(data) ? "1" : "0"))
							? RC_OK : RC_ERR_ALLOC;
	case AVP_ENUMID:
	case AVP_INT32:
		return asprintf(val, "%d", dm_get_int32_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_COUNTER:
	case AVP_UINT32:
		return asprintf(val, "%u", dm_get_uint32_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_ABSTICKS:
	case AVP_RELTICKS:
	case AVP_INT64:
		return asprintf(val, "%" PRIi64, dm_get_int64_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_UINT64:
		return asprintf(val, "%" PRIu64, dm_get_uint64_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_ENUM:
	case AVP_PATH:
	case AVP_STRING:
		return (*val = strndup(data, len)) ? RC_OK : RC_ERR_ALLOC;
	case AVP_BINARY: {
		*val = malloc(((len + 3) * 4) / 3);
		if (!*val)
			return RC_ERR_ALLOC;

		dm_to64(data, len, *val);
		return RC_OK;
	}
	case AVP_ADDRESS:
		if (!dm_get_address_avp(&af, &addr, data) ||
		    af != AF_INET || !(dum = inet_ntoa(addr.in)))
			return RC_ERR_MISC;
		return (*val = strdup(dum)) ? RC_OK : RC_ERR_ALLOC;
	case AVP_DATE:
		return asprintf(val, "%u", (uint32_t)dm_get_time_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	default:
		return RC_ERR_MISC;
	}

	/* never reached */
}

		/* process AVP group returned by dm_send|register_list */
		/* NOTE: this is mainly for backwards compatibility, LISTs can be recursive now. */
		/* it aborts if there's a node containing children, so it should only be used for "level 1" lists */

uint32_t
dm_decode_node_list(DM_AVPGRP *grp, char **name, uint32_t *type,
		    uint32_t *size, uint32_t *datatype)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	DM_AVPGRP	*node_container;

	if (dm_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_CONTAINER || !len)
		return RC_ERR_MISC;

	if (!(node_container = dm_decode_avpgrp(NULL, data, len)))
		return RC_ERR_ALLOC;

	if (dm_avpgrp_get_avp(node_container, &code, &flags, &vendor_id,
				&data, &len) ||
	    code != AVP_NODE_NAME || !len) {
		dm_grp_free(node_container);
		return RC_ERR_MISC;
	}
	if (!(*name = strndup(data, len))) {
		dm_grp_free(node_container);
		return RC_ERR_ALLOC;
	}

	if (dm_avpgrp_get_avp(node_container, &code, &flags, &vendor_id,
				&data, &len) ||
	    code != AVP_NODE_TYPE || len != sizeof(uint32_t)) {
		dm_grp_free(node_container);
		return RC_ERR_MISC;
	}
	*type = dm_get_uint32_avp(data);

	if (*type == NODE_PARAMETER) {
		if (datatype) {
			if (dm_avpgrp_get_avp(node_container, &code, &flags,
						&vendor_id, &data, &len) ||
			    (code == AVP_NODE_DATATYPE && len != sizeof(uint32_t))) {
				dm_grp_free(node_container);
				return RC_ERR_MISC;
			}
			*datatype = code == AVP_NODE_DATATYPE ? dm_get_uint32_avp(data)
							      : code;
		}
	} else if (*type == NODE_OBJECT && size) {
		if (dm_avpgrp_get_avp(node_container, &code, &flags,
					&vendor_id, &data, &len) ||
		    code != AVP_NODE_SIZE || len != sizeof(uint32_t)) {
			dm_grp_free(node_container);
			return RC_ERR_MISC;
		}
		*size = dm_get_uint32_avp(data);
	}

	dm_grp_free(node_container);
	return RC_OK;
}

