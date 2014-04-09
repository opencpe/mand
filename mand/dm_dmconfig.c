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
#include <sys/queue.h>

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmcontext.h"
#include "libdmconfig/dmmsg.h"
#include "libdmconfig/codes.h"

#include "dm.h"
#include "dmd.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_index.h"
#include "dm_cache.h"
#include "dm_serialize.h"
#include "dm_strings.h"
#include "dm_cfg_bkrst.h"
#include "dm_notify.h"
#include "dm_dmconfig.h"
#include "dm_validate.h"
#include "utils/binary.h"

#include "libdmconfig/dm_dmconfig_rpc_skel.h"
#include "libdmconfig/dm_dmconfig_rpc_impl.h"
#include "libdmconfig/dm_dmclient_rpc_stub.h"

#define SDEBUG
#include "debug.h"

#define dm_debug(sid, format, ...) debug(": [#%08X] " format, sid, ## __VA_ARGS__)
#define dm_ENTER(sid) dm_debug(sid, "%s", "enter")
#define dm_EXIT(sid) dm_debug(sid, "%s, %d", "exit", __LINE__)

int libdmconfigSocketType;
uint32_t cfg_session_id;

static DMCONTEXT *accept_socket;

static TAILQ_HEAD(socket_list, sockContext) socket_head = TAILQ_HEAD_INITIALIZER(socket_head);

static uint32_t session_counter;

static uint32_t req_hopid;
static uint32_t req_endid;

static void
end_session(SOCKCONTEXT *ctx)
{
	// TODO: more stuff todo....

	if (ev_is_active(&ctx->session_timer_ev))
		ev_timer_stop(ctx->socket->ev, &ctx->session_timer_ev);

	dm_context_shutdown(ctx->socket, DMCONFIG_OK);
	dm_context_release(ctx->socket);

	if (ctx->notify_slot)
		free_slot(ctx->notify_slot);

	if (cfg_session_id == ctx->id) {
		cfg_session_id = 0;
		cache_reset();
	}

	TAILQ_REMOVE(&socket_head, ctx, list);
	talloc_free(ctx);

	exec_actions_pre();
	exec_actions();
	exec_pending_notifications();
}

static void
sessionTimeoutEvent(struct ev_loop *loop __attribute__((unused)), ev_io *w, int revents __attribute__((unused)))
{
	SOCKCONTEXT *ctx = w->data;

	end_session(ctx);
}

static uint32_t
accept_cb(DMCONFIG_EVENT event, DMCONTEXT *socket, void *userdata __attribute__((unused)))
{
	SOCKCONTEXT *ctx;

	if (event != DMCONFIG_ACCEPTED)
		return RC_OK;

	if (!(ctx = talloc_zero(NULL, SOCKCONTEXT)))
		return RC_ERR_ALLOC;

	dm_context_set_userdata(socket, ctx);
	ctx->socket = socket;

	ev_timer_init(&ctx->session_timer_ev, sessionTimeoutEvent, 0., 0.);
	ctx->session_timer_ev.data = ctx;

	/* ev_timer_start(socket->ev, &ctx->session_timer_ev); */

	TAILQ_INSERT_TAIL(&socket_head, ctx, list);

	return RC_OK;
}

static void
request_cb(DMCONTEXT *socket, DM_PACKET *pkt, DM2_AVPGRP *grp, void *userdata)
{
	SOCKCONTEXT *ctx = userdata;
	DMC_REQUEST req;
	DM2_REQUEST *answer = NULL;

	req.hop2hop = dm_hop2hop_id(pkt);
	req.end2end = dm_end2end_id(pkt);
	req.code = dm_packet_code(pkt);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Received %s:\n",
		dm_packet_flags(pkt) & CMD_FLAG_REQUEST ? "request" : "answer");
	dump_dm_packet(pkt);
#endif

	if (ev_is_active(&ctx->session_timer_ev))
		ev_timer_again(socket->ev, &ctx->session_timer_ev);

	if ((rpc_dmconfig_switch(ctx, &req, grp, &answer)) == RC_ERR_ALLOC) {
		end_session(ctx);
		return;
	}

	if (answer)
		dm_enqueue(socket, answer, REPLY, NULL, NULL);
}

uint32_t
init_libdmconfig_server(struct ev_loop *base)
{
	uint32_t rc;

	if (accept_socket)
		return RC_OK;

	if (!(accept_socket = dm_context_new()))
		return RC_ERR_ALLOC;
	dm_context_init(accept_socket, base, libdmconfigSocketType, NULL, accept_cb, request_cb);

	/* initiate session counter & hop2hop/end2end ids (random value between 1 and MAX_INT) */
	srand((unsigned int)time(NULL));
	session_counter = 1;
	req_hopid = req_endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;

	/* accept */
	if ((rc = dm_accept_async(accept_socket)) != RC_OK)
		goto abort;

	return RC_OK;

 abort:
	dm_context_shutdown(accept_socket, DMCONFIG_ERROR_ACCEPTING);
	return rc;
}

/*
 * RPC Helpers
 */

struct list_ctx {
	DM2_REQUEST	*req;

	int		level;
	int		max_level;
};

static inline uint32_t avp_type_map(unsigned short type)
{
	switch (type) {
	case T_ENUM:		return AVP_ENUM;
	case T_COUNTER:		return AVP_COUNTER;
	case T_INT:		return AVP_INT32;
	case T_UINT:		return AVP_UINT32;
	case T_INT64:		return AVP_INT64;
	case T_UINT64:		return AVP_UINT64;
	case T_STR:		return AVP_STRING;
	case T_BINARY:		return AVP_BINARY;
	case T_BASE64:		return AVP_BINARY;
	case T_IPADDR4:		return AVP_ADDRESS;
	case T_IPADDR6:		return AVP_ADDRESS;
	case T_BOOL:		return AVP_BOOL;
	case T_DATE:		return AVP_DATE;
	case T_SELECTOR:	return AVP_PATH;
	case T_TICKS:		return AVP_TICKS;
	}
	return AVP_UNKNOWN;
}


static uint32_t
dm_add_avp(DM2_REQUEST *req, const struct dm_element *elem, const DM_VALUE val)
{
	switch (elem->type) {
	case T_ENUM:
		debug(": [Answer: %s (%d)]\n", dm_int2enum(&elem->u.e, DM_ENUM(val)), DM_ENUM(val));
		return dm_add_string(req, AVP_ENUM, VP_TRAVELPING, dm_int2enum(&elem->u.e, DM_ENUM(val)));

	case T_COUNTER:
		debug(": [Answer: %u]\n", DM_UINT(val));
		return dm_add_uint32(req, AVP_COUNTER, VP_TRAVELPING, DM_UINT(val));

	case T_INT:
		debug(": [Answer: %d]\n", DM_INT(val));
		return dm_add_int32(req, AVP_INT32, VP_TRAVELPING, DM_INT(val));

	case T_UINT:
		debug(": [Answer: %u]\n", DM_UINT(val));
		return dm_add_uint32(req, AVP_UINT32, VP_TRAVELPING, DM_UINT(val));

	case T_INT64:
		debug(": [Answer: %" PRIi64 "]\n", DM_INT64(val));
		return dm_add_int64(req, AVP_INT64, VP_TRAVELPING, DM_INT64(val));

	case T_UINT64:
		debug(": [Answer: %" PRIu64 " ]\n", DM_UINT64(val));
		return dm_add_uint64(req, AVP_UINT64, VP_TRAVELPING, DM_UINT64(val));

	case T_STR:
		debug(": [Answer: \"%s\"]\n", DM_STRING(val) ? : "");
		return dm_add_string(req, AVP_STRING, VP_TRAVELPING, DM_STRING(val) ? : "");

	case T_BINARY:
	case T_BASE64:
		debug(": [Answer: \"binay data....\"]\n"); /* FIXME */
		return dm_add_raw(req, AVP_BINARY, VP_TRAVELPING,
				  DM_BINARY(val) ? DM_BINARY(val)->data : "",
				  DM_BINARY(val) ? DM_BINARY(val)->len : 0);

	case T_IPADDR4:
		debug(": [Answer: %s]\n", inet_ntoa(DM_IP4(val)));
		return dm_add_address(req, AVP_ADDRESS, VP_TRAVELPING, AF_INET, DM_IP4_REF(val));

	case T_IPADDR6:
		/* debug(": [Answer: %s]\n", inet_ntoa(DM_IP6(val))); */
		return dm_add_address(req, AVP_ADDRESS, VP_TRAVELPING, AF_INET6, DM_IP6_REF(val));

	case T_BOOL:
		debug(": [Answer: %s (%d)]\n", DM_BOOL(val) ? "true" : "false", DM_BOOL(val));
		return dm_add_uint8(req, AVP_BOOL, VP_TRAVELPING, (uint8_t) DM_BOOL(val));

	case T_DATE:
		debug(": [Answer: (%d) %s", (int)DM_TIME(val), ctime(DM_TIME_REF(val)));
		return dm_add_time(req, AVP_DATE, VP_TRAVELPING, DM_TIME(val));

	case T_SELECTOR: {
		char buffer[MAX_PARAM_NAME_LEN];
		char *name;

		if (!DM_SELECTOR(val))
			name = "";
		else if (!(name = dm_sel2name(*DM_SELECTOR(val), buffer, sizeof(buffer))))
			return DM_INVALID_VALUE;

		debug(": [Answer: \"%s\"]\n", name);
		return dm_add_string(req, AVP_PATH, VP_TRAVELPING, name);
	}

	case T_TICKS: {
		uint32_t type = elem->flags & F_DATETIME ? AVP_ABSTICKS : AVP_RELTICKS;
		ticks_t t = type == AVP_ABSTICKS ? ticks2realtime(DM_TICKS(val)) : DM_TICKS(val);

		debug(": [Answer: %" PRItick "]\n", t);
		return dm_add_int64(req, type, VP_TRAVELPING, t);
	}

	default:
		return RC_ERR_INVALID_AVP_TYPE;
	}

	/* never reached */
	return RC_OK;
}

static DM_RESULT
dmconfig_avp2value(const struct dm2_avp *avp, const struct dm_element *elem, DM_VALUE *value)
{
	char		*dum = NULL;
	DM_RESULT	r = DM_OK;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	memset(value, 0, sizeof(DM_VALUE));

	if (avp->code == AVP_UNKNOWN) {
		if (!(dum = strndup(avp->data, avp->size)))
			return DM_OOM;

		switch (elem->type) {
		case T_BASE64:
		case T_BINARY: {	/* dm_string2value cannot be used since it treats T_BASE64 and T_BINARY differently */
			unsigned int len;
			binary_t *n;

			/* this is going to waste some bytes.... */
			len = ((avp->size + 4) * 3) / 4;

			n = malloc(sizeof(binary_t) + len);
			if (!n) {
				r = DM_OOM;
				break;
			}

			debug(": base64 string: %d, buffer: %u", (int)avp->size, len);
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
			if (avp->code != AVP_STRING)
				r = DM_INVALID_TYPE;
			else if (!(dum = strndup(avp->data, avp->size)))
				r = DM_OOM;
			else {
				debug(": = \"%s\"\n", dum);
				r = dm_set_string_value(value, dum);
			}

			break;

		case T_BINARY:
		case T_BASE64:
			if (avp->code != AVP_BINARY)
				r = DM_INVALID_TYPE;
			else {
				debug(": = binary data...\n"); /* FIXME: hex dump for instance... */
				r = dm_set_binary_data(value, avp->size, avp->data);
			}

			break;

		case T_SELECTOR:
			if (avp->code != AVP_PATH)
				r = DM_INVALID_TYPE;
			else if (!(dum = strndup(avp->data, avp->size)))
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

			if (avp->code != AVP_ADDRESS)
				r = DM_INVALID_TYPE;
			else if (!dm_get_address_avp(&af, &addr, sizeof(addr), avp->data, avp->size) ||
				af != AF_INET)
				r = DM_INVALID_VALUE;
			else {
				debug(": = %s\n", inet_ntoa(addr));

				set_DM_IP4(*value, addr);
			}

			break;
		}

		case T_IPADDR6: {
			int		af;
			struct in6_addr addr;

			if (avp->code != AVP_ADDRESS)
				r = DM_INVALID_TYPE;
			else if (!dm_get_address_avp(&af, &addr, sizeof(addr), avp->data, avp->size) ||
				af != AF_INET6)
				r = DM_INVALID_VALUE;
			else {
				/* debug(": = %s\n", inet_ntoa(addr)); */

				set_DM_IP6(*value, addr);
			}

			break;
		}

		case T_ENUM: {
			int enumid;

			switch (avp->code) {
			case AVP_ENUM:
				if (!(dum = strndup(avp->data, avp->size)))
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
				enumid = dm_get_int32_avp(avp->data);
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
			if (avp->code != AVP_INT32)
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT(*value,
					   dm_get_int32_avp(avp->data));
				debug(": = %d\n", DM_INT(*value));
			}

			break;

		case T_UINT:
			if (avp->code != AVP_UINT32)
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT(*value,
					    dm_get_uint32_avp(avp->data));
				debug(": = %u\n", DM_UINT(*value));
			}

			break;

		case T_INT64:
			if (avp->code != AVP_INT64)
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT64(*value,
					     dm_get_int64_avp(avp->data));
				debug(": = %" PRIi64 "\n", DM_INT64(*value));
			}

			break;

		case T_UINT64:
			if (avp->code != AVP_UINT64)
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT64(*value,
					      dm_get_uint64_avp(avp->data));
				debug(": = %" PRIu64 "\n", DM_UINT64(*value));
			}

			break;

		case T_BOOL:
			if (avp->code != AVP_BOOL)
				r = DM_INVALID_TYPE;
			else {
				set_DM_BOOL(*value,
					    dm_get_uint8_avp(avp->data));
				debug(": = %d\n", DM_BOOL(*value));
			}

			break;

		case T_DATE:
			if (avp->code != AVP_DATE)
				r = DM_INVALID_TYPE;
			else {
				set_DM_TIME(*value,
					    dm_get_time_avp(avp->data));
				debug(": = (%d) %s", (int)DM_TIME(*value),
				      ctime(DM_TIME_REF(*value)));
			}

			break;

		case T_TICKS:
			switch (avp->code) {
			case AVP_ABSTICKS: /* FIXME: has to be converted? */
			case AVP_RELTICKS:
				set_DM_TICKS(*value,
					     dm_get_int64_avp(avp->data));
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

	return r;
}


static DM_RESULT
dmconfig_set_cb(void *data, const dm_selector sel,
		const struct dm_element *elem,
		struct dm_value_table *base,
		const void *v, DM_VALUE *st)
{
	SOCKCONTEXT *ctx = data;
	struct dm2_avp *value = (struct dm2_avp *)v;
	DM_VALUE new_value;
	DM_RESULT r;

	if ((r = dmconfig_avp2value(value, elem, &new_value)) != DM_OK)
		return r;

	if (ctx->flags & CMD_FLAG_CONFIGURE) {
		st->flags |= DV_UPDATE_PENDING;
		DM_parity_update(*st);
		cache_add(sel, "", elem, base, st, new_value, 0, NULL);
	} else {
		new_value.flags |= DV_UPDATED;
		DM_parity_update(new_value);
		r = dm_overwrite_any_value_by_selector(sel, elem->type, new_value, ctx->notify_slot ? : -1);
	}

	return r;
}

static DM_RESULT
dmconfig_get_cb(void *data, const dm_selector sb __attribute__((unused)),
		const struct dm_element *elem, const DM_VALUE val)
{
	DM2_REQUEST *req = data;
	uint32_t rc;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	if ((rc = dm_add_avp(req, elem, val)) != RC_OK)
		return DM_OOM;

	return DM_OK;
}

static int
dmconfig_list_cb(void *data, CB_type type, dm_id id, const struct dm_element *elem, const DM_VALUE value)
{
	struct list_ctx	*ctx = data;

	if (!elem->key)
		return 0;

	switch (type) {
	case CB_object_end:
	case CB_table_end:
	case CB_object_instance_end:
		if (ctx->level && ctx->level < ctx->max_level) {
			if (dm_finalize_group(ctx->req) != RC_OK)
				return 0;
		}
		ctx->level--;

		return 1;
	case CB_object_start:
		if ((dm_new_group(ctx->req, AVP_TABLE, VP_TRAVELPING)) != RC_OK
		    || (dm_add_string(ctx->req, AVP_NAME, VP_TRAVELPING, elem->key)) != RC_OK)
			return 0;

		ctx->level++;
		break;

	case CB_object_instance_start:
		if ((dm_new_group(ctx->req, AVP_INSTANCE, VP_TRAVELPING)) != RC_OK
		    || (dm_add_uint16(ctx->req, AVP_NAME, VP_TRAVELPING, id)) != RC_OK)
			return 0;
		ctx->level++;
		break;

	case CB_table_start:
		if ((dm_new_group(ctx->req, AVP_OBJECT, VP_TRAVELPING)) != RC_OK
		    || (dm_add_string(ctx->req, AVP_NAME, VP_TRAVELPING, elem->key)) != RC_OK)
			return 0;
		ctx->level++;
		break;

	case CB_element:
		if ((dm_new_group(ctx->req, AVP_ELEMENT, VP_TRAVELPING)) != RC_OK
		    || (dm_add_string(ctx->req, AVP_NAME, VP_TRAVELPING, elem->key)) != RC_OK
		    || (dm_add_uint32(ctx->req, AVP_TYPE, VP_TRAVELPING, avp_type_map(elem->type))) != RC_OK)
			return 0;

		dm_add_avp(ctx->req, elem, value);

		if (dm_finalize_group(ctx->req) != RC_OK)
			return 0;

		break;

	default:
		return 0;
	}

	return 1;
}

static DM_RESULT
dmconfig_retrieve_enums_cb(void *data,
			   const dm_selector sb __attribute__((unused)),
			   const struct dm_element *elem,
			   const DM_VALUE val __attribute__((unused)))
{
	DM2_REQUEST *req = data;
	const struct dm_enum *enumer;
	char *ptr;
	int i;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	enumer = &elem->u.e;
	for (ptr = enumer->data, i = enumer->cnt; i; i--, ptr += strlen(ptr) + 1)
		if (dm_add_string(req, AVP_STRING, VP_TRAVELPING, ptr) != RC_OK)
			return DM_OOM;

	return DM_OK;
}

/* Note: this kind of encoding should normally got into dm_dmclient_rpc_stub
 */
static uint32_t
build_notify_events(struct notify_queue *queue, int level, DM2_REQUEST *notify)
{
	uint32_t rc;
	struct notify_item *next;

	for (struct notify_item *item = RB_MIN(notify_queue, queue); item; item = next) {
		char buffer[MAX_PARAM_NAME_LEN];
		char *path;

		next = RB_NEXT(notify_queue, queue, item);

		if (item->level != level)
			continue;

		/* active notification */

		if (!(path = dm_sel2name(item->sb, buffer, sizeof(buffer))))
			return RC_ERR_ALLOC;

		if ((rc = dm_add_object(notify) != RC_OK))
			return rc;

		switch (item->type) {
		case NOTIFY_ADD:
			debug(": instance added: %s", path);

			if (((rc = dm_add_uint32(notify, AVP_NOTIFY_TYPE, VP_TRAVELPING, NOTIFY_INSTANCE_CREATED)) != RC_OK)
			    || (rc = dm_add_string(notify, AVP_PATH, VP_TRAVELPING, path)) != RC_OK)
				return rc;
			break;

		case NOTIFY_DEL:
			debug(": instance removed: %s", path);

			if ((rc = dm_add_uint32(notify, AVP_NOTIFY_TYPE, VP_TRAVELPING, NOTIFY_INSTANCE_DELETED)) != RC_OK
			    || (rc = dm_add_string(notify, AVP_PATH, VP_TRAVELPING, path)) != RC_OK)
				return rc;
			break;

		case NOTIFY_CHANGE: {
			struct dm_element *elem;

			debug(": parameter changed: %s", path);

			if (dm_get_element_by_selector(item->sb, &elem) == T_NONE)
				/* this should never, ever, ever happen....*/
				return RC_ERR_MISC;

			if ((rc = dm_add_uint32(notify, AVP_NOTIFY_TYPE, VP_TRAVELPING, NOTIFY_PARAMETER_CHANGED)) != RC_OK
			    || (rc = dm_add_string(notify, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
			    || (rc = dm_add_uint32(notify, AVP_TYPE, VP_TRAVELPING, avp_type_map(elem->type))) != RC_OK
			    || (rc = dm_add_avp(notify, elem, item->value)) != RC_OK)
				return rc;
		}
		}

		if ((rc = dm_finalize_group(notify)) != RC_OK)
			return rc;

		RB_REMOVE(notify_queue, queue, item);
		free(item);
	}

	return RC_OK;
}

/* Note: this kind of encoding should normally got into dm_dmclient_rpc_stub
 */
static void
dmconfig_notify_cb(void *data, struct notify_queue *queue)
{
	SOCKCONTEXT *ctx = data;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_CLIENT_ACTIVE_NOTIFY, CMD_FLAG_REQUEST, 0, 0))
	    || build_notify_events(queue, ACTIVE_NOTIFY, req) != RC_OK
	    || dm_finalize_packet(req) != RC_OK)
		return;

	dm_enqueue(ctx->socket, req, ONE_WAY, NULL, NULL);
}

/*
 * RPC implementations
 */

uint32_t
rpc_startsession(void *data, uint32_t flags, int32_t timeout, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	if (ctx->id)
		return RC_ERR_INVALID_SESSIONID;

	if (flags & CMD_FLAG_CONFIGURE) {
		if (cfg_session_id)
			/* there is already an active config session */
			return RC_ERR_CANNOT_OPEN_CFGSESSION;

		cfg_session_id = session_counter;
	}

	/* start the session */
	ctx->id = session_counter;
	ctx->flags = flags;
	dm_debug(ctx->id, "CMD: START SESSION");

	session_counter++;
	if (session_counter == 0)
		session_counter++;

	if (timeout > 0) {
		ctx->session_timer_ev.repeat = timeout;
		ev_timer_again(ctx->socket->ev, &ctx->session_timer_ev);
	}

	return RC_OK;
}

uint32_t
rpc_switchsession(void *data, uint32_t flags, int32_t timeout, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	if (!ctx->id)
		return RC_ERR_INVALID_SESSIONID;

	if (flags & CMD_FLAG_CONFIGURE) {
		if (cfg_session_id && cfg_session_id != ctx->id)
			/* there is already an active config session */
			return RC_ERR_CANNOT_OPEN_CFGSESSION;

		cfg_session_id = ctx->id;
		dm_debug(ctx->id, "CMD: SWITCH SESSION (r/w to cfg)");
	}
	else if (cfg_session_id == ctx->id) {
		cfg_session_id = 0;
		cache_reset();
		dm_debug(ctx->id, "CMD: SWITCH SESSION (cfg to r/w)");
	}

	ctx->flags = flags;

	if (timeout > 0) {
		ctx->session_timer_ev.repeat = timeout;
		ev_timer_again(ctx->socket->ev, &ctx->session_timer_ev);
	}

	return RC_OK;
}

uint32_t
rpc_endsession(void *data)
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s... ", "END SESSION");

	end_session(ctx);

	return RC_OK;

}

uint32_t
rpc_sessioninfo(void *data, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s... ", "GET SESSION INFO");

	return dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, ctx->flags);
}

uint32_t
rpc_cfgsessioninfo(void *data __attribute__((unused)), DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;

	SOCKCONTEXT *srch;
	uint32_t rc;

	dm_debug(ctx->id, "CMD: %s... ", "GET CONFIGURE SESSION INFO");

	TAILQ_FOREACH(srch, &socket_head, list)
		if (srch->id == cfg_session_id)
			break;

	if (!srch)
		return RC_ERR_INVALID_SESSIONID;


	if ((rc = dm_add_uint32(answer, AVP_SESSIONID, VP_TRAVELPING, cfg_session_id)) != RC_OK
	    || (rc = dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, srch->flags)) != RC_OK)
		return rc;

	return RC_OK;
}

uint32_t
rpc_subscribe_notify(void *data, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s... ", "SUBSCRIBE NOTIFY");

	if (ctx->notify_slot || (ctx->notify_slot = alloc_slot(dmconfig_notify_cb, ctx)) == -1)
		return RC_ERR_CANNOT_SUBSCRIBE_NOTIFY;

	return RC_OK;
}

uint32_t
rpc_unsubscribe_notify(void *data, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: UNSUBSCRIBE NOTIFY... ");

	if (!ctx->notify_slot)
		return RC_ERR_REQUIRES_NOTIFY;

	free_slot(ctx->notify_slot);
	return RC_OK;
}

uint32_t
rpc_param_notify(void *data, uint32_t notify, int pcnt, dm_selector *path, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;
	int i;

	dm_debug(ctx->id, "CMD: %s... ", "PARAM NOTIFY");

	if (!ctx->notify_slot)
		return RC_ERR_REQUIRES_NOTIFY;

	notify = notify ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

	for (i = 0; i < pcnt; i++) {
		char b1[128];
		dm_debug(ctx->id, "CMD: %s \"%s\" (%s)", "PARAM NOTIFY", sel2str(b1, path[i]), notify == ACTIVE_NOTIFY ? "active" : "passive");

		if (dm_set_notify_by_selector(path[i], ctx->notify_slot, notify) != DM_OK)
			return RC_ERR_MISC;
	}

	return RC_OK;
}

uint32_t
rpc_recursive_param_notify(void *data, uint32_t notify, dm_selector path, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;
        char b1[128];

	dm_debug(ctx->id, "CMD: %s \"%s\"... ", "RECURSIVE PARAM NOTIFY", sel2str(b1, path));


	if (!ctx->notify_slot)
		return RC_ERR_REQUIRES_NOTIFY;

	if (dm_set_notify_by_selector_recursive(path, ctx->notify_slot, notify) != DM_OK)
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_get_passive_notifications(void *data, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx = data;
	struct notify_queue *queue;

	dm_debug(ctx->id, "CMD: %s... ", "GET PASSIVE NOTIFICATIONS");

	if (!ctx->notify_slot)
		return RC_ERR_REQUIRES_NOTIFY;

	queue = get_notify_queue(ctx->notify_slot);
	return build_notify_events(queue, PASSIVE_NOTIFY, answer);
}

uint32_t
rpc_db_addinstance(void *data __attribute__((unused)), dm_selector path, dm_id id, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
        char b1[128];
	uint32_t rc;

	dm_debug(ctx->id, "CMD: %s", "DB ADD INSTANCE");
	dm_debug(ctx->id, "CMD: %s \"%s\"", "DB ADD INSTANCE", sel2str(b1, path));
	dm_debug(ctx->id, "CMD: %s id = 0x%hX", "DB ADD INSTANCE", id);

	if (!dm_add_instance_by_selector(path, &id))
		return RC_ERR_MISC;

	if ((rc = dm_add_uint16(answer, AVP_UINT16, VP_TRAVELPING, id)) != RC_OK)
		return rc;

	return RC_OK;
}

uint32_t
rpc_db_delinstance(void *data __attribute__((unused)), dm_selector path, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
        char b1[128];

	/* improvised: check whether this is a table */
	dm_debug(ctx->id, "CMD: %s \"%s\"", "DB DELETE INSTANCE", sel2str(b1, path));

	if (!dm_del_table_by_selector(path))
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_set(void *data, int pvcnt, struct rpc_db_set_path_value *values, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;
	int i, rc;

	dm_debug(ctx->id, "CMD: %s", "DB SET");

	for (i = 0; i < pvcnt; i++) {
		if ((rc = dm_get_value_ref_by_selector_cb(values[i].path, &values[i].value, ctx, dmconfig_set_cb)) == DM_OOM)
			return RC_ERR_ALLOC;
		if (rc != DM_OK)
			return RC_ERR_MISC;
	}

	return RC_OK;
}

uint32_t
rpc_db_get(void *data, int pcnt, dm_selector *values, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx = data;
	GET_BY_SELECTOR_CB get_value;
	int i;

	get_value = cfg_session_id && ctx->id == cfg_session_id ? dm_cache_get_value_by_selector_cb : dm_get_value_by_selector_cb;

	for (i = 0; i < pcnt; i++) {
		char b1[128];

		dm_debug(ctx->id, "CMD: %s \"%s\"", "DB GET", sel2str(b1, values[i]));

		switch (get_value(values[i], T_ANY, answer, dmconfig_get_cb)) {
		case DM_OK:
			continue;
		case DM_OOM:
			return RC_ERR_ALLOC;
		default:
			return RC_ERR_MISC;
		}
	}

	return RC_OK;
}

uint32_t
rpc_db_list(void *data __attribute__((unused)), int level, dm_selector path, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
	struct list_ctx list_ctx;

	dm_debug(ctx->id, "CMD: %s", "DB LIST");

	memset(&list_ctx, 0, sizeof(struct list_ctx));
	list_ctx.req = answer;
	list_ctx.max_level = level ? : DM_SELECTOR_LEN;

	if (!dm_walk_by_selector_cb(path, level ? level + 1 : DM_SELECTOR_LEN, &list_ctx, dmconfig_list_cb))
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_retrieve_enum(void *data, dm_selector path, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
        char b1[128];

	dm_debug(ctx->id, "CMD: %s \"%s\"", "DB RETRIEVE ENUMS", sel2str(b1, path));

	switch (dm_get_value_by_selector_cb(path, T_ENUM, answer, dmconfig_retrieve_enums_cb)) {
	case DM_OK:
		return RC_OK;
	case DM_OOM:
		return RC_ERR_ALLOC;
	default:
		return RC_ERR_MISC;
	}

	return RC_OK;
}

uint32_t
rpc_db_dump(void *data, char *path, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
	char *buf;
	long tsize;
	size_t r = 0;
	FILE *tf;

	dm_debug(ctx->id, "CMD: %s \"%s\"", "DB DUMP", path);

	tf = tmpfile();
	if (!tf)
		return RC_ERR_MISC;

	if (path && *path)
		dm_serialize_element(tf, path, S_ALL);
	else
		dm_serialize_store(tf, S_ALL);

	tsize = ftell(tf);
	fseek(tf, 0, SEEK_SET);

	if (!tsize) {
		fclose(tf);
		return RC_ERR_MISC;
	}

	buf = malloc(tsize);
	if (buf)
		r = fread(buf, tsize, 1, tf);
	fclose(tf);
	if (r != 1) {
		free(buf);
		return RC_ERR_MISC;
	}

	if (dm_add_raw(answer, AVP_STRING, VP_TRAVELPING, buf, tsize))
		return RC_ERR_ALLOC;

	free(buf);
	return RC_OK;
}

/* saves running config to persistent storage */
uint32_t
rpc_db_save(void *data, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s", "DB SAVE");

	if (ctx->id == cfg_session_id && !cache_is_empty())		/* cache not empty */
		return RC_ERR_MISC;

	dm_save();
	return RC_OK;
}

/* commits cache to running config and tries to apply changes */
uint32_t
rpc_db_commit(void *data, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s", "DB COMMIT");

	if (ctx->id != cfg_session_id)
		return RC_ERR_REQUIRES_CFGSESSION;

	if (cache_validate()) {
		exec_actions_pre();
		cache_apply(ctx->notify_slot ? : -1);
		exec_actions();
		exec_pending_notifications();
	} else
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_cancel(void *data, DM2_REQUEST *answer __attribute__((unused)))
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s", "DB CANCEL");

	if (ctx->id != cfg_session_id)
		return RC_ERR_REQUIRES_CFGSESSION;

	cache_reset();
	return RC_OK;
}

uint32_t
rpc_db_findinstance(void *data __attribute__((unused)), const dm_selector path, const struct dm_bin *name, const struct dm2_avp *search, DM2_REQUEST *answer)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
	const struct dm_table *kw;
	dm_id param;
	struct dm_instance_node *inst;
	DM_VALUE value;

	dm_debug(ctx->id, "CMD: %s", "DB FINDINSTANCE");

	/* find table structure */
	if (!(kw = dm_get_object_table_by_selector(path)))
		return RC_ERR_MISC;

	if ((param = dm_get_element_id_by_name(name->data, name->size, kw)) == DM_ERR)
		return RC_ERR_MISC;

	dm_debug(ctx->id, "CMD: %s: parameter id: %u", "DB FINDINSTANCE", param);

	dm_debug(ctx->id, "CMD: %s: value", "DB FINDINSTANCE");
	switch (dmconfig_avp2value(search, kw->table + param - 1, &value)) {
	case DM_OOM:
		return RC_ERR_ALLOC;
	case DM_OK:
		break;
	default:
		return RC_ERR_MISC;
	}

	inst = find_instance_by_selector(path, param, kw->table[param - 1].type, &value);
	dm_free_any_value(kw->table + param - 1, &value);
	if (!inst)
		return RC_ERR_MISC;

	dm_debug(ctx->id, "CMD: %s: answer: %u", "DB FINDINSTANCE", inst->instance);

	if (dm_add_uint16(answer, AVP_UINT16, VP_TRAVELPING, inst->instance))
		return RC_ERR_ALLOC;

	return RC_OK;
}

void dm_event_broadcast(const dm_selector sel, enum dm_action_type type)
{
	char buffer[MAX_PARAM_NAME_LEN];
	char *path;
	SOCKCONTEXT *ctx;

	if (!(path = dm_sel2name(sel, buffer, sizeof(buffer))))
		return;

	TAILQ_FOREACH(ctx, &socket_head, list)
		rpc_event_broadcast(ctx->socket, path, type);
}
