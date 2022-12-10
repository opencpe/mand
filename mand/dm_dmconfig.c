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
#include <sys/ioctl.h>
#include <signal.h>

#include <sys/tree.h>
#include <net/if.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>

#include <sys/time.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <netlink/route/neighbour.h>

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
#include "process.h"

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

void
end_session(SOCKCONTEXT *ctx)
{
	dm_context_set_userdata(ctx->socket, NULL);

	if (ev_is_active(&ctx->session_timer_ev))
		ev_timer_stop(ctx->socket->ev, &ctx->session_timer_ev);

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

void
shutdown_session(SOCKCONTEXT *ctx)
{
	dm_context_shutdown(ctx->socket, DMCONFIG_OK);
	dm_context_release(ctx->socket);

	end_session(ctx);
}

static void
sessionTimeoutEvent(struct ev_loop *loop __attribute__((unused)), ev_timer *w, int revents __attribute__((unused)))
{
	SOCKCONTEXT *ctx = w->data;

	shutdown_session(ctx);
}

static uint32_t
accept_cb(DMCONFIG_EVENT event, DMCONTEXT *socket, void *userdata)
{
	SOCKCONTEXT *ctx;

	if (event != DMCONFIG_ACCEPTED) {
		if (userdata)
			end_session((SOCKCONTEXT *)userdata);
		return RC_OK;
	}

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

	struct dm_request_info *request_info = talloc_zero(NULL, struct dm_request_info);
	if (!request_info)
		return;
	request_info->ctx = ctx;

	if ((rpc_dmconfig_switch(ctx, &req, grp, request_info)) == RC_ERR_ALLOC) {
		shutdown_session(ctx);
		talloc_free(request_info);
		return;
	}

	/*
	 * FIXME: Perhaps we should move this into rpc_dmconfig_switch().
	 * However, we don't have the DMCONTEXT type there.
	 * It could be added to struct dm_request_info, though.
	 */
	if (request_info->answer && !talloc_reference_count(request_info))
		dm_enqueue(socket, request_info->answer, REPLY, NULL, NULL);
	talloc_unlink(NULL, request_info);
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

static uint32_t dm_add_avp(DM2_REQUEST *req, const struct dm_element *elem, int st_type, const DM_VALUE val);

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

static int
dm_add_array_avp_cb(void *data, CB_type type, dm_id id __attribute__((unused)), const struct dm_element *elem, const DM_VALUE value)
{
	DM2_REQUEST *req = data;

	debug(": %s, type: %d\n", elem->key, type);

	switch (type) {
	case CB_object_end:
		if (dm_finalize_group(req) != RC_OK)
			return 0;
		break;

	case CB_object_start:
		if ((dm_new_group(req, AVP_ARRAY, VP_TRAVELPING)) != RC_OK)
			return 0;
		break;

	case CB_element:
		dm_add_avp(req, elem, T_ELEMENT, value);
		break;

	default:
		break;
	}

	return 1;
}

static uint32_t
dm_add_array_avp(DM2_REQUEST *req, const struct dm_element *elem, const DM_VALUE val)
{
	if (dm_walk_object_cb(16, req, dm_add_array_avp_cb, -1, elem, val))
		return RC_OK;
	return RC_ERR_MISC;
}

static uint32_t
dm_add_avp(DM2_REQUEST *req, const struct dm_element *elem, int st_type, const DM_VALUE val)
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
				  DM_BINARY(val) ? DM_BINARY(val)->data : (const uint8_t *)"",
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

	case T_TOKEN:
		debug(": [Answer: TABLE]\n");
		return dm_add_uint32(req, AVP_TYPE, VP_TRAVELPING, AVP_TABLE);

	case T_OBJECT:
		if (elem->flags & F_ARRAY)
			return dm_add_array_avp(req, elem, val);

		switch (st_type) {
		case T_OBJECT:
			debug(": [Answer: OBJECT]\n");
			return dm_add_uint32(req, AVP_TYPE, VP_TRAVELPING, AVP_OBJECT);
		case T_INSTANCE:
			debug(": [Answer: INSTANCE]\n");
			return dm_add_uint32(req, AVP_TYPE, VP_TRAVELPING, AVP_INSTANCE);
		}
		return RC_ERR_INVALID_AVP_TYPE;

	default:
		return RC_ERR_INVALID_AVP_TYPE;
	}

	/* never reached */
	return RC_OK;
}

static DM_RESULT
dmconfig_string2value(char *s, size_t size, const struct dm_element *elem, DM_VALUE *value)
{
	char *dum = NULL;
	DM_RESULT r = DM_OK;
	int ilen = size;

	debug(": %s: %*s", elem->key, ilen, s);

	if (!(dum = strndup(s, size)))
		return DM_OOM;

	switch (elem->type) {
	case T_BASE64:
	case T_BINARY: {	/* dm_string2value cannot be used since it treats T_BASE64 and T_BINARY differently */
		unsigned int len;
		binary_t *n;

		/* this is going to waste some bytes.... */
		len = ((size + 4) * 3) / 4;

		n = malloc(sizeof(binary_t) + len);
		if (!n) {
			r = DM_OOM;
			break;
		}

		debug(": base64 string: %d, buffer: %u", (int)size, len);
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

	free(dum);
	return r;
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
		return dmconfig_string2value(avp->data, avp->size, elem, value);
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
dmconfig_set_array_cb(SOCKCONTEXT *ctx __attribute__((unused)),
		      const dm_selector sel,
		      const struct dm_element *elem,
		      struct dm_value_table *base __attribute__((unused)),
		      struct dm2_avp *avp,
		      DM_VALUE *st)
{
	int len = avp->size;
	DM_RESULT rc;
	char buffer[MAX_PARAM_NAME_LEN];
	char *path;

	if (elem->type != T_OBJECT
	    || st->type != T_OBJECT
	    || (avp->code != AVP_UNKNOWN && avp->code != AVP_ARRAY))
		return DM_INVALID_TYPE;

	if (!(path = dm_sel2name(sel, buffer, sizeof(buffer))))
		return DM_OOM;

	debug(": %08x:%08x, %d, %d, %s (%s): %*s", avp->vendor_id, avp->code, elem->type, st->type, elem->key, path, len, (char *)avp->data);

	if (!dm_del_table_by_selector(sel))
		return DM_ERROR;

	if (avp->code == AVP_UNKNOWN) {
		debug(": string2array");

		dm_id id = 1;
		char *s = avp->data;
		size_t rem = avp->size;
		char *p;

		while (rem) {
			size_t s_len;
			struct dm_instance_node *node;
			DM_VALUE *value;

			p = memchr(s, ',', rem);
			s_len = (p != NULL) ? (size_t)(p - s) : rem;

			if (!(node = dm_add_instance_by_selector(sel, &id)))
				return DM_OOM;

			value = dm_get_value_ref_by_index(DM_TABLE(node->table), 0);

			if ((rc = dmconfig_string2value(s, s_len, &elem->u.t.table->table[0], value)) != DM_OK)
				return rc;

			value->flags |= DV_UPDATED;
			DM_parity_update(*value);

			update_instance_node_index(node);

			id++;
			rem -= s_len;
			s = p + 1;
		}
	} else {
		debug(": list2array");

		dm_id id = 1;
		DM2_AVPGRP container;

		dm_init_avpgrp(NULL, avp->data, avp->size, &container);

		while (dm_expect_group_end(&container) != RC_OK) {
			struct dm2_avp a;
			struct dm_instance_node *node;
			DM_VALUE *value;

			if (dm_expect_value(&container, &a) != RC_OK)
				return DM_ERROR;

			if (!(node = dm_add_instance_by_selector(sel, &id)))
				return DM_OOM;

			value = dm_get_value_ref_by_index(DM_TABLE(node->table), 0);

			if ((rc = dmconfig_avp2value(&a, &elem->u.t.table->table[0], value)) != DM_OK)
				return rc;

			value->flags |= DV_UPDATED;
			DM_parity_update(*value);

			update_instance_node_index(node);

			id++;
		}
	}

	return DM_OK;
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

	if (elem->flags & F_ARRAY)
		return dmconfig_set_array_cb(ctx, sel, elem, base, value, st);

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
		const struct dm_element *elem, int st_type, const DM_VALUE val)
{
	DM2_REQUEST *req = data;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	if (dm_add_avp(req, elem, st_type, val) != RC_OK)
		return DM_ERROR;

	return DM_OK;
}

static int
dmconfig_list_array_cb(struct list_ctx *ctx, CB_type type, const struct dm_element *elem, const DM_VALUE value)
{
	debug(": %s, type: %d", elem->key, type);

	switch (type) {
	case CB_object_end:
		if (ctx->level && ctx->level < ctx->max_level) {
			if (dm_finalize_group(ctx->req) != RC_OK)
				return 0;
		}
		ctx->level--;

		return 1;

	case CB_object_start:
		if ((dm_new_group(ctx->req, AVP_ARRAY, VP_TRAVELPING)) != RC_OK
		    || (dm_add_string(ctx->req, AVP_NAME, VP_TRAVELPING, elem->key)) != RC_OK
		    || (dm_add_uint32(ctx->req, AVP_TYPE, VP_TRAVELPING, avp_type_map(elem->type))) != RC_OK)
			return 0;

		ctx->level++;
		break;

	case CB_element:
		dm_add_avp(ctx->req, elem, T_ELEMENT, value);
		break;

	default:
		break;
	}

	return 1;
}

static int
dmconfig_list_cb(void *data, CB_type type, dm_id id, const struct dm_element *elem, const DM_VALUE value)
{
	struct list_ctx *ctx = data;

	if (!elem->key)
		return 0;

	if (elem->flags & F_ARRAY)
		return dmconfig_list_array_cb(ctx, type, elem, value);

	switch (type) {
	case CB_object_instance_end:
	case CB_object_end:
	case CB_table_end:
		if (ctx->level && ctx->level <= ctx->max_level) {
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

		dm_add_avp(ctx->req, elem, T_ELEMENT, value);

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
			   int st_type __attribute__((unused)),
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
			    || (rc = dm_add_avp(notify, elem, T_ELEMENT, item->value)) != RC_OK)
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

static SOCKCONTEXT *find_role(const char *role)
{
	SOCKCONTEXT *srch;

	TAILQ_FOREACH(srch, &socket_head, list)
		if (srch->role && strcmp(srch->role, role) == 0)
			break;

	return srch;
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

	shutdown_session(ctx);

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
		rc = dm_get_value_ref_by_selector_cb(values[i].path, &values[i].value, ctx, dmconfig_set_cb);
		switch (rc) {
		case RC_OK:
			continue;

		case DM_OOM:
			return RC_ERR_ALLOC;

		case DM_INVALID_VALUE:
		case DM_INVALID_TYPE:
			return RC_ERR_INVALID_AVP_TYPE;

		case DM_VALUE_NOT_FOUND:
			return RC_ERR_VALUE_NOT_FOUND;

		case 0x8000 ... 0x8FFF:
			return rc;

		default:
			return RC_ERR_MISC;
		}
	}

	return RC_OK;
}

uint32_t
rpc_db_get(void *data, int pcnt, dm_selector *values, DM2_REQUEST *answer)
{
	uint32_t rc;
	SOCKCONTEXT *ctx = data;
	GET_BY_SELECTOR_CB get_value;
	int i;

	get_value = cfg_session_id && ctx->id == cfg_session_id ? dm_cache_get_value_by_selector_cb : dm_get_value_by_selector_cb;

	for (i = 0; i < pcnt; i++) {
		char b1[128];

		dm_debug(ctx->id, "CMD: %s \"%s\"", "DB GET", sel2str(b1, values[i]));

		rc = get_value(values[i], T_ANY, answer, dmconfig_get_cb);
		switch (rc) {
		case RC_OK:
			continue;

		case DM_OOM:
			return RC_ERR_ALLOC;

		case DM_INVALID_VALUE:
		case DM_INVALID_TYPE:
			return RC_ERR_INVALID_AVP_TYPE;

		case DM_VALUE_NOT_FOUND:
			return RC_ERR_VALUE_NOT_FOUND;

		case 0x8000 ... 0x8FFF:
			return rc;

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
	list_ctx.max_level = level ? level + 1 : DM_SELECTOR_LEN;

	if (path[0]) {
		if (!dm_walk_by_selector_cb(path, level ? level + 1 : DM_SELECTOR_LEN, &list_ctx, dmconfig_list_cb))
			return RC_ERR_MISC;
	} else
		if (!dm_walk_table_cb(level ? level + 1 : DM_SELECTOR_LEN, &list_ctx, dmconfig_list_cb, &dm_root, dm_value_store))
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

uint32_t rpc_register_role(void *data, const char *role)
{
	SOCKCONTEXT *ctx = data;

	dm_debug(ctx->id, "CMD: %s %s", "REGISTER_ROLE", role);

	/* check if this ctx already has a role */
	if (ctx->role)
		return (strcmp(ctx->role, role) == 0) ? RC_OK : RC_ERR_MISC;

	/* check if someone else has this role */
	if (find_role(role) != NULL)
		return RC_ERR_MISC;

	/* add role */
	ctx->role = talloc_strdup(ctx, role);
	dm_debug(ctx->id, "CMD: %s %s: success", "REGISTER_ROLE", role);

	return RC_OK;
}

uint32_t rpc_system_restart(void *data __attribute__((unused)))
{
	vsystem("/sbin/reboot");

	return RC_OK;
}

uint32_t rpc_system_shutdown(void *data __attribute__((unused)))
{
	vsystem("/sbin/poweroff");

	return RC_OK;
}

static void
rpc_firmware_download_cb(DMCONTEXT *socket __attribute__((unused)), DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	uint32_t rc = RC_OK;
	struct dm_request_info *request_info = userdata;
	SOCKCONTEXT *ctx = request_info->ctx;

	if (event != DMCONFIG_ANSWER_READY) {
		rc = RC_ERR_MISC;
		goto response;
	}

	if (dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &rc) != RC_OK) {
		rc = RC_ERR_MISC;
		goto response;
	}

	int32_t job_id;
	if ((rc = dm_expect_int32_type(grp, AVP_INT32, VP_TRAVELPING, &job_id)) != RC_OK
	    || (rc = dm_expect_group_end(grp)) != RC_OK)
		goto response;

	dm_debug(ctx->id, "CMD: %s: answer: %u", "FIRMWARE DOWNLOAD", job_id);

response:
	if (rc == RC_OK) {
		if (dm_add_int32(request_info->answer, AVP_INT32, VP_TRAVELPING, job_id) != RC_OK)
			return;
	} else {
		/* fill in the RC */
		dm_put_uint32_at_pos(request_info->answer, request_info->rc_pos, rc);
	}
	if (dm_finalize_packet(request_info->answer) != RC_OK)
		return;

	dm_enqueue(ctx->socket, request_info->answer, REPLY, NULL, NULL);
	talloc_free(request_info);
}

uint32_t rpc_firmware_download(void *data, char *address, uint8_t credentialstype, char *credential,
                               char *install_target, uint32_t timeframe, uint8_t retry_count,
                               uint32_t retry_interval, uint32_t retry_interval_increment,
                               struct dm_request_info *request_info)
{
	SOCKCONTEXT *ctx = data;
	SOCKCONTEXT *clnt;
	uint32_t rc;

	dm_debug(ctx->id, "CMD: %s", "FIRMWARE DOWNLOAD");

	if ((clnt = find_role("-firmware")) == NULL) {
		talloc_free(request_info);
		return RC_ERR_MISC;
	}

	rc = rpc_agent_firmware_download_async(clnt->socket, address, credentialstype, credential,
	                                       install_target, timeframe, retry_count,
	                                       retry_interval, retry_interval_increment,
	                                       rpc_firmware_download_cb, request_info);
	if (rc != RC_OK) {
		logx(LOG_ERR, "rpc_agent_firmware_download_async rc=%d\n", rc);
		return rc;
	}

	return RC_OK;
}

static void
rpc_firmware_commit_cb(DMCONTEXT *socket __attribute__((unused)), DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	uint32_t rc = RC_OK;
	struct dm_request_info *request_info = userdata;
	SOCKCONTEXT *ctx = request_info->ctx;

	if (event != DMCONFIG_ANSWER_READY) {
		rc = RC_ERR_MISC;
		goto response;
	}

	if (dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &rc) != RC_OK) {
		rc = RC_ERR_MISC;
		goto response;
	}

	dm_debug(ctx->id, "CMD: %s: answer: %u", "FIRMWARE COMMIT", rc);

response:
	if (rc != RC_OK)
		/* fill in the RC */
		dm_put_uint32_at_pos(request_info->answer, request_info->rc_pos, rc);
	if (dm_finalize_packet(request_info->answer) != RC_OK)
		return;

	dm_enqueue(ctx->socket, request_info->answer, REPLY, NULL, NULL);
	talloc_free(request_info);
}

uint32_t rpc_firmware_commit(void *data, int32_t job_id,
                             struct dm_request_info *request_info)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
	SOCKCONTEXT *clnt;
	uint32_t rc;

	dm_debug(ctx->id, "CMD: %s: %u", "FIRMWARE COMMIT", job_id);

	if ((clnt = find_role("-firmware")) == NULL)
		return RC_ERR_MISC;

	rc = rpc_agent_firmware_commit_async(clnt->socket, job_id,
	                                     rpc_firmware_commit_cb, request_info);
	if (rc != RC_OK) {
		logx(LOG_ERR, "rpc_agent_firmware_commit_async rc=%d\n", rc);
		return rc;
	}

	return RC_OK;
}

static void
rpc_set_boot_order_cb(DMCONTEXT *socket __attribute__((unused)), DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	uint32_t rc = RC_OK;
	struct dm_request_info *request_info = userdata;
	SOCKCONTEXT *ctx = request_info->ctx;

	if (event != DMCONFIG_ANSWER_READY) {
		rc = RC_ERR_MISC;
		goto response;
	}

	if (dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &rc) != RC_OK) {
		rc = RC_ERR_MISC;
		goto response;
	}

	dm_debug(ctx->id, "CMD: %s: answer: %u", "SET BOOT ORDER", rc);

response:
	if (rc != RC_OK)
		/* fill in the RC */
		dm_put_uint32_at_pos(request_info->answer, request_info->rc_pos, rc);
	if (dm_finalize_packet(request_info->answer) != RC_OK)
		return;

	dm_enqueue(ctx->socket, request_info->answer, REPLY, NULL, NULL);
	talloc_free(request_info);
}

uint32_t rpc_set_boot_order(void *data, int pcnt, const char **boot_order,
                            struct dm_request_info *request_info)
{
	SOCKCONTEXT *ctx __attribute__((unused)) = data;
	SOCKCONTEXT *clnt;
	uint32_t rc;

	dm_debug(ctx->id, "CMD: %s", "SET BOOT ORDER");

	if ((clnt = find_role("-firmware")) == NULL)
		return RC_ERR_MISC;

	rc = rpc_agent_set_boot_order_async(clnt->socket, pcnt, boot_order,
	                                    rpc_set_boot_order_cb, request_info);
	if (rc != RC_OK) {
		logx(LOG_ERR, "rpc_agent_set_boot_order_async rc=%d\n", rc);
		return rc;
	}

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

static int sys_scan(const char *file, const char *fmt, ...)
{
	FILE *fin;
	int rc, _errno;
	va_list vlist;

	fin = fopen(file, "r");
	if (!fin) {
		errno = 0;
		return EOF;
	}

	va_start(vlist, fmt);
	errno = 0;
	rc = vfscanf(fin, fmt, vlist);
	_errno = errno;
	va_end(vlist);

	fclose(fin);

	errno = _errno;
	return rc;
}

static uint32_t if_ioctl(int d, int request, void *data)
{
	int result;

	if (ioctl(d, request, data) == -1) {
		do {
			result = close(d);
		} while (result == -1 && errno == EINTR);
		return RC_ERR_MISC;
	}
	return RC_OK;
}

static void
update_neigh_state_ip4(struct nl_object *obj, void *data)
{
	dm_selector *sel = data;

	char buf[32];
	struct rtnl_neigh *neigh = (struct rtnl_neigh *)obj;

	struct in_addr dst;
	memcpy(&dst.s_addr, nl_addr_get_binary_addr(rtnl_neigh_get_dst(neigh)), sizeof(dst.s_addr));
	struct nl_addr *lladdr = rtnl_neigh_get_lladdr(neigh);
	uint32_t state = rtnl_neigh_get_state(neigh);
	nl_addr2str(lladdr, buf, sizeof(buf));
	uint8_t origin = (state == NUD_PERMANENT) ? 1 : 2;

	dm_id if_id = 0;

	struct dm_instance_node *ipn;
	if (!(ipn = dm_add_instance_by_selector(*sel, &if_id)))
		return;

	dm_set_ipv4_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv4__neighbor_ip, dst);
	dm_set_string_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv4__neighbor_linklayeraddress, buf);
	dm_set_enum_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv4__neighbor_origin, origin);

	update_instance_node_index(ipn);

	logx(LOG_DEBUG, "IPV4 Neighbor %d", if_id);
}

static void
update_neigh_state_ip6(struct nl_object *obj, void *data)
{
	dm_selector *sel = data;

	char buf[32];
	struct rtnl_neigh *neigh = (struct rtnl_neigh *)obj;

	struct in6_addr dst;
	memcpy(dst.s6_addr, nl_addr_get_binary_addr(rtnl_neigh_get_dst(neigh)), sizeof(dst.s6_addr));
	struct nl_addr *lladdr = rtnl_neigh_get_lladdr(neigh);
	uint32_t state = rtnl_neigh_get_state(neigh);
	uint32_t flags = rtnl_neigh_get_flags(neigh);
	nl_addr2str(lladdr, buf, sizeof(buf));
	uint8_t origin = (state == NUD_PERMANENT) ? 1 : 2;
	uint8_t is_router = ((flags & NTF_ROUTER) != 0);

	dm_id if_id = 0;

	struct dm_instance_node *ipn;
	if (!(ipn = dm_add_instance_by_selector(*sel, &if_id)))
		return;

	dm_set_ipv6_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__neighbor_ip, dst);
	dm_set_string_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__neighbor_linklayeraddress, buf);
	dm_set_enum_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__neighbor_origin, origin);
	dm_set_bool_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__neighbor_isrouter, is_router);

	update_instance_node_index(ipn);

	logx(LOG_DEBUG, "IPV6 Neighbor %d", if_id);
}

static void
update_addr_state_ip4(struct nl_object *obj, void *data)
{
	dm_selector *sel = data;

	char buf[32];
	struct nl_addr *naddr = rtnl_addr_get_local((struct rtnl_addr *) obj);
	struct in_addr addr;
	memcpy(&addr.s_addr, nl_addr_get_binary_addr(naddr), sizeof(addr.s_addr));
	unsigned int flags = rtnl_addr_get_flags((struct rtnl_addr *) obj);
	uint8_t origin = 0;

	logx(LOG_DEBUG, "IP: %s", nl_addr2str(naddr, buf, sizeof(buf)));

	if (flags & IFA_F_PERMANENT)
		origin = 1;

	dm_id if_id = 0;

	struct dm_instance_node *ipn;
	if (!(ipn = dm_add_instance_by_selector(*sel, &if_id)))
		return;
	logx(LOG_DEBUG, "IPV4 Addr %d", if_id);

	dm_set_ipv4_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv4__address_ip, addr);
	dm_set_uint_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv4__address_prefixlength,
	                  nl_addr_get_prefixlen(naddr));
	dm_set_enum_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv4__address_origin, origin);

	update_instance_node_index(ipn);
}

static void
update_addr_state_ip6(struct nl_object *obj, void *data)
{
	dm_selector *sel = data;

	char buf[32];
	struct nl_addr *naddr = rtnl_addr_get_local((struct rtnl_addr *) obj);
	struct in6_addr addr;
	memcpy(addr.s6_addr, nl_addr_get_binary_addr(naddr), sizeof(addr.s6_addr));
	unsigned int flags = rtnl_addr_get_flags((struct rtnl_addr *) obj);
	uint8_t origin = 0;
	uint8_t status = 4;

	logx(LOG_DEBUG, "IP: %s", nl_addr2str(naddr, buf, sizeof(buf)));

	if (flags & IFA_F_OPTIMISTIC)
		status = 7;
	else if (flags & IFA_F_TENTATIVE)
		status = 5;
	else if (flags & IFA_F_HOMEADDRESS)
		status = 0;
	else if (flags & IFA_F_DEPRECATED)
		status = 1;

	if (flags & IFA_F_PERMANENT)
		origin = 1;

	dm_id if_id = 0;

	struct dm_instance_node *ipn;
	if (!(ipn = dm_add_instance_by_selector(*sel, &if_id)))
		return;
	logx(LOG_DEBUG, "IPV6 Addr %d", if_id);

	dm_set_ipv6_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__address_ip, addr);
	dm_set_uint_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__address_prefixlength,
	                  nl_addr_get_prefixlen(naddr));
	dm_set_enum_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__address_origin, origin);
	dm_set_enum_by_id(DM_TABLE(ipn->table), field_ocpe__interfaces_state__interface__ipv6__address_status, status);

	update_instance_node_index(ipn);
}

static void
update_route_state_nh_ipv4(struct rtnl_nexthop *nh, void *data)
{
	dm_selector *sel = data;

	struct nl_addr *addr = rtnl_route_nh_get_gateway(nh);
	if (!addr)
		return;

	dm_id id = 0;
	struct dm_instance_node *ipn = dm_add_instance_by_selector(*sel, &id);
	if (!ipn)
		return;

	struct in_addr dst;
	memcpy(&dst.s_addr, nl_addr_get_binary_addr(addr), sizeof(dst.s_addr));
	/* interfaces.interface.ipv4.gateway-ip[id] */
	dm_set_ipv4_by_id(DM_TABLE(ipn->table), 1, dst);
}

static void
update_route_state_ip4(struct nl_object *obj, void *data)
{
	struct rtnl_route *route = (struct rtnl_route *)obj;
	rtnl_route_foreach_nexthop(route, update_route_state_nh_ipv4, data);
}

static void
update_route_state_nh_ip6(struct rtnl_nexthop *nh, void *data)
{
	dm_selector *sel = data;

	struct nl_addr *addr = rtnl_route_nh_get_gateway(nh);
	if (!addr)
		return;

	dm_id id = 0;
	struct dm_instance_node *ipn = dm_add_instance_by_selector(*sel, &id);
	if (!ipn)
		return;

	struct in6_addr dst;
	memcpy(dst.s6_addr, nl_addr_get_binary_addr(addr), sizeof(dst.s6_addr));
	/* interfaces.interface.ipv6.gateway-ip[id] */
	dm_set_ipv6_by_id(DM_TABLE(ipn->table), 1, dst);
}

static void
update_route_state_ip6(struct nl_object *obj, void *data)
{
	struct rtnl_route *route = (struct rtnl_route *)obj;
	rtnl_route_foreach_nexthop(route, update_route_state_nh_ip6, data);
}

static uint32_t update_interface_state(struct dm_value_table *tbl)
{
	/*
	 * Make sure the interface is reported as "down" in case of any errors.
	 * This will also include missing interfaces.
	 */
	dm_set_enum_by_id(tbl, field_ocpe__interfaces_state__interface_adminstatus ,
			  field_ocpe__interfaces_state__interface_adminstatus_down);
	dm_set_enum_by_id(tbl, field_ocpe__interfaces_state__interface_operstatus ,
			  field_ocpe__interfaces_state__interface_operstatus_down);

	const char *if_name = dm_get_string_by_id(tbl, field_ocpe__interfaces_state__interface_name);
	logx(LOG_DEBUG, "get_ocpe__interfaces_state__interface: %s", if_name);

	char macstr[20];
	ticks_t rt_now = ticks();

	int fd;
	FILE *fp;
	char line[1024];
	struct ifreq ifr;
	uint32_t rc;

	int scan_count;

	logx(LOG_DEBUG, "if_name: %s", if_name);

	const char *dev = if_name;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1)
		return RC_ERR_MISC;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	if ((rc = if_ioctl(fd, SIOCGIFINDEX, &ifr)) != RC_OK) {
		close(fd);
		return rc;
	}
	if (ifr.ifr_ifindex == 0)
		ifr.ifr_ifindex = 2147483647;
	int32_t if_index = ifr.ifr_ifindex;

	if ((rc = if_ioctl(fd, SIOCGIFFLAGS, &ifr)) != RC_OK) {
		close(fd);
		return rc;
	}
	uint32_t if_flags = ifr.ifr_flags;

	if ((rc = if_ioctl(fd, SIOCGIFHWADDR, &ifr)) != RC_OK) {
		close(fd);
		return rc;
	}
	uint8_t mac[6];
	memcpy(mac, &ifr.ifr_hwaddr, sizeof(mac));

	struct ethtool_cmd cmd;
	ifr.ifr_data = (void *)&cmd;
	cmd.cmd = ETHTOOL_GSET; /* "Get settings" */
	uint32_t if_speed = 0;
	if ((rc = if_ioctl(fd, SIOCETHTOOL, &ifr)) == RC_OK)
		if_speed = ethtool_cmd_speed(&cmd);

	close(fd);

	if (!(fp = fopen("/proc/net/dev", "r")))
		return RC_ERR_MISC;

	if (!fgets(line, sizeof(line), fp)) /* ignore first line */
		logx(LOG_ERR, "Cannot parse /proc/net/dev");
	if (!fgets(line, sizeof(line), fp))
		logx(LOG_ERR, "Cannot parse /proc/net/dev");

        uint64_t rec_pkt = 0, rec_oct = 0, rec_err = 0, rec_drop = 0;
        uint64_t snd_pkt = 0, snd_oct = 0, snd_err = 0, snd_drop = 0;

	while (!feof(fp)) {
		char device[32];

		scan_count = fscanf(fp, " %32[^:]:%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %*u %*u %*u %*u %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %*u %*u %*s",
				    device,
				    &rec_oct, &rec_pkt, &rec_err, &rec_drop,
				    &snd_oct, &snd_pkt, &snd_err, &snd_drop);
		if (scan_count == 9 && strcmp(dev, device) == 0)
			break;
	}
	fclose(fp);

	if (dm_get_ticks_by_id(tbl, field_ocpe__interfaces_state__interface_lastchange) == 0)
		dm_set_ticks_by_id(tbl, field_ocpe__interfaces_state__interface_lastchange , rt_now);

	dm_set_int_by_id(tbl, field_ocpe__interfaces_state__interface_ifindex , if_index);
	dm_set_enum_by_id(tbl, field_ocpe__interfaces_state__interface_adminstatus ,
			  (if_flags & IFF_UP) ? field_ocpe__interfaces_state__interface_adminstatus_up : field_ocpe__interfaces_state__interface_adminstatus_down);
	dm_set_enum_by_id(tbl, field_ocpe__interfaces_state__interface_operstatus ,
			  (if_flags & IFF_UP) ? field_ocpe__interfaces_state__interface_operstatus_up : field_ocpe__interfaces_state__interface_operstatus_down);

	snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	dm_set_string_by_id(tbl, field_ocpe__interfaces_state__interface_physaddress , macstr);

	dm_set_uint64_by_id(tbl, field_ocpe__interfaces_state__interface_speed, if_speed);

	struct dm_value_table *stats;

	stats = dm_get_table_by_id(tbl, field_ocpe__interfaces_state__interface_statistics);

	if (dm_get_ticks_by_id(stats, field_ocpe__interfaces_state__interface__statistics_discontinuitytime) == 0)
		dm_set_ticks_by_id(stats, field_ocpe__interfaces_state__interface__statistics_discontinuitytime, rt_now);

	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_inoctets, rec_oct);
	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_inunicastpkts, rec_pkt);
//	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_inbroadcastpkts,       );
//	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_inmulticastpkts,       );
	dm_set_uint_by_id(stats, field_ocpe__interfaces_state__interface__statistics_indiscards, rec_drop);
	dm_set_uint_by_id(stats, field_ocpe__interfaces_state__interface__statistics_inerrors, rec_err);
//	dm_set_uint_by_id(stats, field_ocpe__interfaces_state__interface__statistics_inunknownprotos,       );
	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_outoctets, snd_oct);
	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_outunicastpkts, snd_pkt);
//	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_outbroadcastpkts,       );
//	dm_set_uint64_by_id(stats, field_ocpe__interfaces_state__interface__statistics_outmulticastpkts,       );
	dm_set_uint_by_id(stats, field_ocpe__interfaces_state__interface__statistics_outdiscards, snd_drop);
	dm_set_uint_by_id(stats, field_ocpe__interfaces_state__interface__statistics_outerrors, snd_err);

	/* read IP's from NL */

	int ifindex;
	struct nl_sock *socket = nl_socket_alloc();
	struct nl_cache *link_cache = NULL;
	struct nl_cache *addr_cache = NULL;
	struct nl_cache *neigh_cache = NULL;
	struct nl_cache *route_cache = NULL;
	struct rtnl_neigh *neigh_filter = NULL;
	struct rtnl_route *route_filter = NULL;
	struct rtnl_addr *addr_filter = NULL;
	struct nl_addr *route_dst = NULL;
	int forward;
	uint32_t mtu;

	if (nl_connect(socket, NETLINK_ROUTE) < 0) {
		rc = RC_ERR_MISC;
		goto cleanup;
	}

	if (rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache) < 0
	    || rtnl_addr_alloc_cache(socket, &addr_cache) < 0
	    || rtnl_neigh_alloc_cache(socket, &neigh_cache) < 0
	    || rtnl_route_alloc_cache(socket, AF_UNSPEC, 0, &route_cache) < 0) {
		rc = RC_ERR_ALLOC;
		goto cleanup;
	}

	struct rtnl_link *link = rtnl_link_get_by_name(link_cache, dev);
	ifindex = rtnl_link_get_ifindex(link);
	mtu = rtnl_link_get_mtu(link);
	if (mtu == 0 || mtu > 65535)
		mtu = 65535;
	rtnl_link_put(link);

	addr_filter = rtnl_addr_alloc();
	rtnl_addr_set_ifindex(addr_filter, ifindex);

	snprintf(line, sizeof(line), "/proc/sys/net/ipv4/conf/%s/forwarding", dev);
	sys_scan(line, "%u", &forward);
	logx(LOG_DEBUG, "IPv4 Forward: %d", forward);

	char buffer[MAX_PARAM_NAME_LEN];
	dm_selector sel;
	struct dm_value_table *iftbl;

	/* IPv4 Interface */

	dm_selcpy(sel, tbl->id);
	sel[3] = field_ocpe__interfaces_state__interface_ipv4;
	sel[4] = 0;

	dm_sel2name(sel, buffer, sizeof(buffer));
	logx(LOG_DEBUG, "interface: %s", buffer);

	if (!(iftbl = dm_get_table_by_selector(sel))) {
		rc = RC_ERR_MISC;
		goto cleanup;
	}
	dm_set_bool_by_id(iftbl, field_ocpe__interfaces_state__interface__ipv4_forwarding, forward);
	dm_set_uint_by_id(iftbl, field_ocpe__interfaces_state__interface__ipv4_mtu, mtu);

	/* IPv4 Addr */

	sel[4] = field_ocpe__interfaces_state__interface__ipv4_address;
	sel[5] = 0;

	dm_sel2name(sel, buffer, sizeof(buffer));
	logx(LOG_DEBUG, "interface: %s", buffer);

	dm_del_table_by_selector(sel);
	dm_add_table_by_selector(sel);

	rtnl_addr_set_family(addr_filter, AF_INET);

	nl_cache_foreach_filter(addr_cache, (struct nl_object *) addr_filter, update_addr_state_ip4, sel);

	/* IPv4 Neighbor */

	sel[4] = field_ocpe__interfaces_state__interface__ipv4_neighbor;
	sel[5] = 0;

	dm_sel2name(sel, buffer, sizeof(buffer));
	logx(LOG_DEBUG, "interface: %s", buffer);

	dm_del_table_by_selector(sel);
	dm_add_table_by_selector(sel);

	neigh_filter = rtnl_neigh_alloc();
	rtnl_neigh_set_ifindex(neigh_filter, ifindex);

	rtnl_neigh_set_family(neigh_filter, AF_INET);

	nl_cache_foreach_filter(neigh_cache, (struct nl_object *) neigh_filter, update_neigh_state_ip4, sel);

	/* IPv4 Routes/Gateway */

	sel[4] = field_ocpe__interfaces_state__interface__ipv4_gatewayip;
	sel[5] = 0;

	route_filter = rtnl_route_alloc();

	struct rtnl_nexthop *nh = rtnl_route_nh_alloc();
	rtnl_route_nh_set_ifindex(nh, ifindex);
	/* This apparently passes ownership of nh */
	rtnl_route_add_nexthop(route_filter, nh);

	route_dst = nl_addr_build(AF_INET, NULL, 0);
	if (!route_dst) {
		rc = RC_ERR_MISC;
		goto cleanup;
	}
	rtnl_route_set_dst(route_filter, route_dst);

	rtnl_route_set_family(route_filter, AF_INET);

	dm_del_table_by_selector(sel);
	nl_cache_foreach_filter(route_cache, (struct nl_object *)route_filter, update_route_state_ip4, sel);

	/* IPv6 Interface */

	dm_selcpy(sel, tbl->id);
	sel[3] = field_ocpe__interfaces_state__interface_ipv6;
	sel[4] = 0;

	dm_sel2name(sel, buffer, sizeof(buffer));
	logx(LOG_DEBUG, "interface: %s", buffer);

	if (!(iftbl = dm_get_table_by_selector(sel))) {
		rc = RC_ERR_MISC;
		goto cleanup;
	}

	snprintf(line, sizeof(line), "/proc/sys/net/ipv6/conf/%s/forwarding", dev);
	sys_scan(line, "%u", &forward);
	logx(LOG_DEBUG, "IPv6 Forward: %d", forward);

	dm_set_bool_by_id(iftbl, field_ocpe__interfaces_state__interface__ipv6_forwarding, forward);
	dm_set_uint_by_id(iftbl, field_ocpe__interfaces_state__interface__ipv6_mtu, mtu);

	/* IPv6 Addr */

	sel[4] = field_ocpe__interfaces_state__interface__ipv6_address;
	sel[5] = 0;

	dm_sel2name(sel, buffer, sizeof(buffer));
	logx(LOG_DEBUG, "interface: %s", buffer);

	dm_del_table_by_selector(sel);
	dm_add_table_by_selector(sel);

	rtnl_addr_set_family(addr_filter, AF_INET6);

	nl_cache_foreach_filter(addr_cache, (struct nl_object *) addr_filter, update_addr_state_ip6, sel);

	/* IPv6 Neighbor */

	sel[4] = field_ocpe__interfaces_state__interface__ipv6_neighbor;
	sel[5] = 0;

	dm_sel2name(sel, buffer, sizeof(buffer));
	logx(LOG_DEBUG, "interface: %s", buffer);

	dm_del_table_by_selector(sel);
	dm_add_table_by_selector(sel);

	rtnl_neigh_set_family(neigh_filter, AF_INET6);

	nl_cache_foreach_filter(neigh_cache, (struct nl_object *) neigh_filter, update_neigh_state_ip6, sel);

	/* IPv6 Routes/Gateway */

	sel[4] = field_ocpe__interfaces_state__interface__ipv6_gatewayip;
	sel[5] = 0;

	nl_addr_set_family(route_dst, AF_INET6);
	rtnl_route_set_family(route_filter, AF_INET6);

	dm_del_table_by_selector(sel);
	nl_cache_foreach_filter(route_cache, (struct nl_object *)route_filter, update_route_state_ip6, sel);

	rc = RC_OK;

cleanup:
	if (route_dst)
		nl_addr_put(route_dst);
	if (link_cache)
		nl_cache_free(link_cache);
	if (route_cache)
		nl_cache_free(route_cache);
	if (neigh_cache)
		nl_cache_free(neigh_cache);
	if (addr_cache)
		nl_cache_free(addr_cache);
	if (addr_filter)
		rtnl_addr_put(addr_filter);
	if (neigh_filter)
		rtnl_neigh_put(neigh_filter);
	if (route_filter)
		rtnl_route_put(route_filter);
	nl_socket_free(socket);

	return rc;
}

int set_ocpe__system_state__clock_currentdatetime(struct dm_value_table *tbl __attribute__((unused)),
						  dm_id id __attribute__((unused)),
						  const struct dm_element *e __attribute__((unused)),
						  DM_VALUE *st __attribute__((unused)),
						  DM_VALUE val __attribute__((unused)))
{
	struct timeval tv;

	*st = val;

	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = DM_TICKS(*st) / 10;

	fprintf(stderr, "Set DateTime to %"PRItick"\n", DM_TICKS(*st));

	settimeofday(&tv, NULL);

	return 0;
}

DM_VALUE get_ocpe__system_state__clock_currentdatetime(struct dm_value_table *tbl __attribute__((unused)),
						       dm_id id __attribute__((unused)),
						       const struct dm_element *e __attribute__((unused)),
						       DM_VALUE val __attribute__((unused)))
{
	ticks_t rt_now = ticks();

	return init_DM_TICKS(rt_now, 0);
}

DM_VALUE get_ocpe__system__clock_timezoneutcoffset(struct dm_value_table *tbl __attribute__((unused)),
						       dm_id id __attribute__((unused)),
						       const struct dm_element *e __attribute__((unused)),
						       DM_VALUE val __attribute__((unused)))
{
	time_t currentTime = time(NULL);
	struct tm *localTime;
	localTime = localtime(&currentTime);

	return init_DM_INT(localTime->tm_gmtoff / 60, 0);
}

DM_VALUE __get_ocpe__interfaces_state__interface(struct dm_value_table *tbl, dm_id id, const struct dm_element *e, DM_VALUE val __attribute__((unused)))
{
	ticks_t rt_now = ticks();
	ticks_t last = 0;

	char buf1[40], buf2[40];

	last = dm_get_ticks_by_id(tbl, field_ocpe__interfaces_state__interface_lastread);
	ticks2str(buf1, sizeof(buf1), ticks2realtime(last));
	ticks2str(buf2, sizeof(buf2), ticks2realtime(rt_now));

	/*
	 * FIXME: Disables all notifications.
	 * The dmconfig client querying this information does not need them
	 * and the others cannot rely on notifications anyway.
	 * This should be solved more elegantly, though.
	 */
	int notify_enabled_old = notify_enabled;
	notify_enabled = 0;

	/*
	 * FIXME: Perhaps we no longer need to restrict the frequency of update_interface_state()-
	 */
	printf("get_ocpe__interfaces_state__interface: %s: %s, %s, %" PRItick "\n", e->key, buf1, buf2, rt_now - last);
	if (rt_now - last > 10)
		update_interface_state(tbl);

	dm_set_ticks_by_id(tbl, field_ocpe__interfaces_state__interface_lastread, rt_now);

	notify_enabled = notify_enabled_old;

	return *dm_get_value_ref_by_id(tbl, id);
}

DM_VALUE get_ocpe__interfaces_state__interface_adminstatus(struct dm_value_table *tbl, dm_id id, const struct dm_element *e, DM_VALUE val) __attribute__ ((alias ("__get_ocpe__interfaces_state__interface")));

static void update_address_netmask(struct dm_value_table *tbl, dm_id read, dm_id update)
{
	char buf[INET_ADDRSTRLEN];
	uint32_t length;
	struct in_addr mask;
	length = dm_get_uint_by_id(tbl, read);

	if (length < 32)
		mask.s_addr = htonl(0xFFFFFFFF << (32 - length));
	else
		mask.s_addr = 0xFFFFFFFF;

	inet_ntop(AF_INET, &mask, buf, sizeof(buf));
	dm_set_string_by_id(tbl, update, buf);
}

static void update_address_prefixlength(struct dm_value_table *tbl, const char *s, dm_id update)
{
	struct in_addr mask;
	uint32_t length;

	inet_pton(AF_INET, s, &mask);
	length = 33 - ffs(ntohl(mask.s_addr));
	dm_set_uint_by_id(tbl, update, length);
}

int set_ocpe__interfaces__interface__ipv4__address_prefixlength(struct dm_value_table *tbl,
								dm_id id __attribute__((unused)),
								const struct dm_element *e __attribute__((unused)),
								DM_VALUE *st,
								DM_VALUE val)
{
	*st = val;
	update_address_netmask(tbl, field_ocpe__interfaces__interface__ipv4__address_prefixlength,
			            field_ocpe__interfaces__interface__ipv4__address_netmask);
	return DM_OK;
}

int set_ocpe__interfaces__interface__ipv4__address_netmask(struct dm_value_table *tbl,
							   dm_id id __attribute__((unused)),
							   const struct dm_element *e __attribute__((unused)),
							   DM_VALUE *st,
							   DM_VALUE val)
{
	int r;

	if (val.type != T_STR)
		return DM_INVALID_TYPE;

	if ((r = dm_set_string_value(st, DM_STRING(val))) != DM_OK)
		return r;

	update_address_prefixlength(tbl, DM_STRING(val), field_ocpe__interfaces__interface__ipv4__address_prefixlength);
	return DM_OK;
}

DM_VALUE get_ocpe__interfaces__interface__ipv4__address_netmask(struct dm_value_table *tbl,
								dm_id id,
								const struct dm_element *e __attribute__((unused)),
								DM_VALUE val)
{
	if (DM_STRING(val))
		return val;

	update_address_netmask(tbl, field_ocpe__interfaces__interface__ipv4__address_prefixlength,
			            field_ocpe__interfaces__interface__ipv4__address_netmask);
	return *dm_get_value_ref_by_id(tbl, id);
}

DM_VALUE get_ocpe__interfaces_state__interface__ipv4__address_netmask(struct dm_value_table *tbl,
								      dm_id id,
								      const struct dm_element *e __attribute__((unused)),
								      DM_VALUE val __attribute__((unused)))
{
	update_address_netmask(tbl, field_ocpe__interfaces_state__interface__ipv4__address_prefixlength,
			            field_ocpe__interfaces_state__interface__ipv4__address_netmask);
	return *dm_get_value_ref_by_id(tbl, id);
}
