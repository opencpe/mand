/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm_dmconfig.h"
#include "dm_dmconfig_rpc_impl.h"

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

/*
 * Helpers
 */

struct rpc_db_set_info {
	SESSION	*session;
	struct dm2_avp value;
};

struct rpc_db_get_info {
	void *ctx;
	uint32_t type;
	DM_AVPGRP **answer;
};

struct list_ctx {
	void		*ctx;
	DM_AVPGRP	**answer;

	int		level;
	int		max_level;
	int		firstone;
};

static DM_RESULT
dmconfig_value2avp(struct rpc_db_get_info *info,
		   const struct dm_element *elem, const DM_VALUE val);

static uint32_t
build_notify_events(struct notify_queue *queue, int level, DM_OBJ **answer)
{
	struct notify_item *next;

	for (struct notify_item *item = RB_MIN(notify_queue, queue); item; item = next) {
		char		buffer[MAX_PARAM_NAME_LEN];
		char		*path;
		DM_AVPGRP	*event;

		next = RB_NEXT(notify_queue, queue, item);

		if (item->level != level)
			continue;

		/* active notification */

		if (!(path = dm_sel2name(item->sb, buffer, sizeof(buffer)))
		    || !(event = new_dm_avpgrp(*answer)))
			return RC_ERR_ALLOC;

		switch (item->type) {
		case NOTIFY_ADD:
			debug(": instance added: %s", path);

			if (dm_avpgrp_add_uint32(*answer, &event, AVP_NOTIFY_TYPE, 0, VP_TRAVELPING, NOTIFY_INSTANCE_CREATED)
			    || dm_avpgrp_add_string(*answer, &event, AVP_PATH, 0, VP_TRAVELPING, path))
				return RC_ERR_ALLOC;
			break;

		case NOTIFY_DEL:
			debug(": instance removed: %s", path);

			if (dm_avpgrp_add_uint32(*answer, &event, AVP_NOTIFY_TYPE, 0, VP_TRAVELPING, NOTIFY_INSTANCE_DELETED)
			    || dm_avpgrp_add_string(*answer, &event, AVP_PATH, 0, VP_TRAVELPING, path))
				return RC_ERR_ALLOC;
			break;

		case NOTIFY_CHANGE: {
			DM_AVPGRP *grp;
			struct rpc_db_get_info info = {
				.ctx = *answer,
				.type = AVP_UNKNOWN,
				.answer = &grp,
			};
			struct dm_element *elem;

			debug(": parameter changed: %s", path);

			if (dm_avpgrp_add_uint32(*answer, &event, AVP_NOTIFY_TYPE, 0, VP_TRAVELPING, NOTIFY_PARAMETER_CHANGED))
				return RC_ERR_ALLOC;

			if (!(grp = new_dm_avpgrp(*answer))
			    || dm_get_element_by_selector(item->sb, &elem) == T_NONE
			    || dmconfig_value2avp(&info, elem, item->value) != DM_OK)
				return RC_ERR_ALLOC;

			if (dm_avpgrp_add_uint32_string(*answer, &event, AVP_TYPE_PATH, 0, VP_TRAVELPING, info.type, path) ||
			    dm_avpgrp_insert_avpgrp(*answer, &event, grp))
				return RC_ERR_ALLOC;
			break;
		}
		}

		if (dm_avpgrp_add_avpgrp(NULL, answer, AVP_CONTAINER, 0, VP_TRAVELPING, event))
			return RC_ERR_ALLOC;

		talloc_free(event);
		RB_REMOVE(notify_queue, queue, item);
		free(item);
	}

	return RC_OK;
}

static void
dmconfig_notify_cb(void *data, struct notify_queue *queue)
{
	SESSION			*session = data;
	NOTIFY_INFO		*notify = &session->notify;

	DM_AVPGRP		*grp, *dummy;
	int			r;

	dm_ENTER(session->sessionid);

	if (!(grp = new_dm_avpgrp(NULL))) {
		dm_EXIT(session->sessionid);
		return;
	}

	if (build_notify_events(queue, ACTIVE_NOTIFY, &grp) != RC_OK) {
		dm_EXIT(session->sessionid);
		return;
	}

	if (!(dummy = new_dm_avpgrp(NULL))) {
		talloc_free(grp);
		dm_EXIT(session->sessionid);
		return;
	}

	r = dm_avpgrp_add_avpgrp(NULL, &dummy, AVP_CONTAINER, 0, VP_TRAVELPING, grp);
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
	SESSION *le = (SESSION *)data;
	struct dm2_avp *value = (struct dm2_avp *)v;
	DM_VALUE new_value;
	DM_RESULT r;

	if ((r = dmconfig_avp2value(value, elem, &new_value)) != DM_OK)
		return r;

	if (le->flags & CMD_FLAG_CONFIGURE) {
		st->flags |= DV_UPDATE_PENDING;
		DM_parity_update(*st);
		cache_add(sel, "", elem, base, st, new_value, 0, NULL);
	} else {
		new_value.flags |= DV_UPDATED;
		DM_parity_update(new_value);
		r = dm_overwrite_any_value_by_selector(sel, elem->type,
						       new_value,
						       le->notify.slot ? : -1);
	}

	return r;
}

static DM_RESULT
dmconfig_value2avp(struct rpc_db_get_info *info,
		   const struct dm_element *elem, const DM_VALUE val)
{
	switch (elem->type) {
	case T_ENUM:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_ENUM;
		case AVP_ENUM:
			if (dm_avpgrp_add_string(NULL, info->answer, AVP_ENUM, 0, VP_TRAVELPING, dm_int2enum(&elem->u.e, DM_ENUM(val))))
				return DM_OOM;

			debug(": [Answer: %s (%d)]\n",
			      dm_int2enum(&elem->u.e, DM_ENUM(val)),
			      DM_ENUM(val));
			return DM_OK;

		case AVP_ENUMID:
			if (dm_avpgrp_add_int32(NULL, info->answer, AVP_ENUMID, 0, VP_TRAVELPING, DM_ENUM(val)))
				return DM_OOM;

			debug(": [Answer: %s (%d)]\n", dm_int2enum(&elem->u.e, DM_ENUM(val)), DM_ENUM(val));
			return DM_OK;

		default:
			return DM_INVALID_TYPE;
		}
	case T_COUNTER:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_COUNTER;
		case AVP_COUNTER:
			if (dm_avpgrp_add_uint32(NULL, info->answer, AVP_COUNTER, 0, VP_TRAVELPING, DM_UINT(val)))
				return DM_OOM;

			debug(": [Answer: %u]\n", DM_UINT(val));
			return DM_OK;
		default:
			return DM_INVALID_TYPE;
		}
	case T_INT:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_INT32;
		case AVP_INT32:
			if (dm_avpgrp_add_int32(NULL, info->answer, AVP_INT32, 0, VP_TRAVELPING, DM_INT(val)))
				return DM_OOM;

			debug(": [Answer: %d]\n", DM_INT(val));
			return DM_OK;
		default:
			return DM_INVALID_TYPE;
		}
	case T_UINT:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_UINT32;
		case AVP_UINT32:
			if (dm_avpgrp_add_uint32(NULL, info->answer, AVP_UINT32, 0, VP_TRAVELPING, DM_UINT(val)))
				return DM_OOM;

			debug(": [Answer: %u]\n", DM_UINT(val));
			return DM_OK;
		default:
			return DM_INVALID_TYPE;
		}
	case T_INT64:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_INT64;
		case AVP_INT64:
			if (dm_avpgrp_add_int64(NULL, info->answer, AVP_INT64, 0, VP_TRAVELPING, DM_INT64(val)))
				return DM_OOM;

			debug(": [Answer: %" PRIi64 "]\n", DM_INT64(val));
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_UINT64:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_UINT64;
		case AVP_UINT64:
			if (dm_avpgrp_add_uint64(NULL, info->answer, AVP_UINT64, 0, VP_TRAVELPING, DM_UINT64(val)))
				return DM_OOM;

			debug(": [Answer: %" PRIu64 " ]\n", DM_UINT64(val));
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_STR:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_STRING;
		case AVP_STRING:
			if (dm_avpgrp_add_string(NULL, info->answer, AVP_STRING, 0, VP_TRAVELPING, DM_STRING(val) ? : ""))
				return DM_OOM;

			debug(": [Answer: \"%s\"]\n", DM_STRING(val) ? : "");
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_BINARY:
	case T_BASE64:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_BINARY;
		case AVP_BINARY:
			if (dm_avpgrp_add_raw(NULL, info->answer,
						AVP_BINARY, 0, VP_TRAVELPING,
						DM_BINARY(val) ? DM_BINARY(val)->data : "",
						DM_BINARY(val) ? DM_BINARY(val)->len : 0))
				return DM_OOM;

			debug(": [Answer: \"binay data....\"]\n"); /* FIXME */
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_IPADDR4:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_ADDRESS;
		case AVP_ADDRESS:
			if (dm_avpgrp_add_address(NULL, info->answer, AVP_ADDRESS, 0, VP_TRAVELPING, AF_INET, DM_IP4_REF(val)))
				return DM_OOM;

			debug(": [Answer: %s]\n", inet_ntoa(DM_IP4(val)));
			return DM_OK;
		default:
			return DM_INVALID_TYPE;
		}
	case T_IPADDR6:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_ADDRESS;
		case AVP_ADDRESS:
			if (dm_avpgrp_add_address(NULL, info->answer, AVP_ADDRESS, 0, VP_TRAVELPING, AF_INET6, DM_IP6_REF(val)))
				return DM_OOM;

			/* debug(": [Answer: %s]\n", inet_ntoa(DM_IP6(val))); */
			return DM_OK;
		default:
			return DM_INVALID_TYPE;
		}
	case T_BOOL:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_BOOL;
		case AVP_BOOL:
			if (dm_avpgrp_add_uint8(NULL, info->answer, AVP_BOOL, 0, VP_TRAVELPING, (uint8_t) DM_BOOL(val)))
				return DM_OOM;

			debug(": [Answer: %s (%d)]\n", DM_BOOL(val) ? "true" : "false", DM_BOOL(val));
			return DM_OK;
		default:
			return DM_INVALID_TYPE;
		}
	case T_DATE:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_DATE;
		case AVP_DATE:
			if (dm_avpgrp_add_time(NULL, info->answer,
						 AVP_DATE, 0, VP_TRAVELPING,
						 DM_TIME(val)))
				return DM_OOM;

			debug(": [Answer: (%d) %s", (int)DM_TIME(val), ctime(DM_TIME_REF(val)));
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_SELECTOR:
		switch (info->type) {
		case AVP_UNKNOWN:
			info->type = AVP_PATH;
		case AVP_PATH: {
			char buffer[MAX_PARAM_NAME_LEN];
			char *name;

			if (!DM_SELECTOR(val))
				name = "";
			else if (!(name = dm_sel2name(*DM_SELECTOR(val), buffer, sizeof(buffer))))
				return DM_INVALID_VALUE;

			if (dm_avpgrp_add_string(NULL, info->answer, AVP_PATH, 0, VP_TRAVELPING, name))
				return DM_OOM;

			debug(": [Answer: \"%s\"]\n", name);
			return DM_OK;
		}
		default:
			return DM_INVALID_TYPE;
		}
	case T_TICKS:
		if (info->type == AVP_UNKNOWN)
			info->type = elem->flags & F_DATETIME ? AVP_ABSTICKS : AVP_RELTICKS;

		switch (info->type) {
		case AVP_ABSTICKS:
		case AVP_RELTICKS: {
			ticks_t t = info->type == AVP_ABSTICKS ? ticks2realtime(DM_TICKS(val)) : DM_TICKS(val);

			if (dm_avpgrp_add_int64(NULL, info->answer, info->type, 0, VP_TRAVELPING, t))
				return DM_OOM;

			debug(": [Answer: %" PRItick "]\n", t);
			return DM_OK;
		}
		default:
			return DM_INVALID_TYPE;
		}
	default:
		return DM_INVALID_TYPE;
	}

	/* never reached */
	return DM_ERROR;
}


static DM_RESULT
dmconfig_get_cb(void *data, const dm_selector sb __attribute__((unused)),
		const struct dm_element *elem, const DM_VALUE val)
{
	return elem ? dmconfig_value2avp(data, elem, val)
		    : DM_VALUE_NOT_FOUND;
}

static int
dmconfig_list_cb(void *data, CB_type type, dm_id id,
		 const struct dm_element *elem, const DM_VALUE value)
{
#if 0
	/* TODO: fix the get_info mess */

	struct list_ctx		*ctx = data;
	struct rpc_db_get_info	get_info = {
		.ctx = ctx->ctx,
		.type = AVP_UNKNOWN,
	};

	uint32_t		node_type;

	char			*node_name = elem->key;
	char			numbuf[UINT16_DIGITS];

	if (!node_name)
		return 0;

	if (ctx->firstone) {		/* hack that prevents the first element from being processed */
		ctx->firstone = 0;	/* later dm_walk_by_name might be modified or reimplemented */
		return 1;
	}

	switch (type) {
	case CB_object_end:
	case CB_table_end:
	case CB_object_instance_end:
		if (ctx->level && ctx->level < ctx->max_level) {
			get_info.grp = ctx->ctx;
			get_info.ctx = talloc_parent(get_info.grp);

			if (dm_avpgrp_add_avpgrp(get_info.ctx, &get_info.grp, AVP_CONTAINER, 0, VP_TRAVELPING, ctx->grp))
				return 0;
			talloc_free(ctx->grp);

			ctx->grp = get_info.ctx;
			ctx->ctx = talloc_parent(ctx->grp);

			if (dm_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER, 0, VP_TRAVELPING, get_info.grp))
				return 0;

			talloc_free(get_info.grp);
		}
		ctx->level--;

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
		return 0;
	}

	get_info.ctx = ctx->grp;
	if (!(get_info.grp = new_dm_avpgrp(get_info.ctx)))
		return 0;

	if (dm_avpgrp_add_string(get_info.ctx, &get_info.grp, AVP_NODE_NAME, 0, VP_TRAVELPING, node_name))
		return 0;

	if (dm_avpgrp_add_uint32(get_info.ctx, &get_info.grp, AVP_NODE_TYPE, 0, VP_TRAVELPING, node_type))
		return 0;

	switch (node_type) {
	case NODE_PARAMETER:
		if (elem->type == T_POINTER) {
			if (dm_avpgrp_add_uint32(get_info.ctx, &get_info.grp, AVP_NODE_DATATYPE, 0, VP_TRAVELPING, AVP_POINTER))
				return 0;
		} else if (dmconfig_value2avp(&get_info, elem, value))
			return 0;

		if (dm_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER, 0, VP_TRAVELPING, get_info.grp))
			return 0;

		talloc_free(get_info.grp);

		break;

	case NODE_TABLE:
	case NODE_OBJECT:
		if (ctx->level < ctx->max_level) {
			ctx->ctx = get_info.grp;
			if (!(ctx->grp = new_dm_avpgrp(ctx->ctx)))
				return 0;
		} else {
			if ((node_type == NODE_OBJECT
			     && dm_avpgrp_add_uint32(get_info.ctx, &get_info.grp, AVP_NODE_SIZE, 0, VP_TRAVELPING, elem->u.t.table->size))
			    || dm_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER, 0, VP_TRAVELPING, get_info.grp))
				return 0;
			talloc_free(get_info.grp);
		}
	}
#endif
	return 1;
}

		/* used by CMD_DB_LIST request */
static DM_RESULT
dmconfig_retrieve_enums_cb(void *data,
			   const dm_selector sb __attribute__((unused)),
			   const struct dm_element *elem,
			   const DM_VALUE val __attribute__((unused)))
{
	DM_OBJ **answer = data;
	const struct dm_enum *enumer;
	char *ptr;
	int i;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	enumer = &elem->u.e;
	for (ptr = enumer->data, i = enumer->cnt; i; i--, ptr += strlen(ptr) + 1)
		if (dm_avpgrp_add_string(*answer, answer, AVP_STRING, 0, VP_TRAVELPING, ptr))
			return DM_OOM;

	return DM_OK;
}

/*
 * RPC implementations
 */
uint32_t
rpc_startsession(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *grp)
{
	struct event_base *base = NULL;   /* TODO: put evbase into sockCtx */

	return process_request_session(base, sockCtx, req->code, req->hop2hop, req->sessionid, grp);
}

uint32_t
rpc_switchsession(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *grp)
{
	struct event_base *base = NULL;   /* TODO: put evbase into sockCtx */

	return process_request_session(base, sockCtx, req->code, req->hop2hop, req->sessionid, grp);
}

uint32_t
rpc_endsession(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req)
{
	dm_debug(req->sessionid, "CMD: %s... ", "END SESSION");

	return process_end_session(req->sessionid);
}

uint32_t
rpc_sessioninfo(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, DM_OBJ **answer)
{
	SESSION *le;

	dm_debug(req->sessionid, "CMD: %s... ", "GET SESSION INFO");

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	return dm_avpgrp_add_uint32(*answer, answer, AVP_UINT32, 0, VP_TRAVELPING, le->flags);
}

uint32_t
rpc_cfgsessioninfo(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, DM_OBJ **answer)
{
	SESSION *le;
	uint32_t rc;

	dm_debug(req->sessionid, "CMD: %s... ", "GET CONFIGURE SESSION INFO");

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	if (!(le = lookup_session(cfg_sessionid)))
		return RC_ERR_MISC;

	if ((rc = dm_avpgrp_add_uint32(*answer, answer, AVP_SESSIONID, 0, VP_TRAVELPING, cfg_sessionid)) != RC_OK
	    || (rc = dm_avpgrp_add_uint32(*answer, answer, AVP_UINT32, 0, VP_TRAVELPING, le->flags)) != RC_OK
	    || (rc = dm_avpgrp_add_timeval(*answer, answer, AVP_TIMEVAL, 0, VP_TRAVELPING, le->timeout_session)) != RC_OK)
		return rc;

	return RC_OK;
}

uint32_t
rpc_subscribe_notify(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req)
{
	SESSION *le;
	int slot;

	dm_debug(req->sessionid, "CMD: %s... ", "SUBSCRIBE NOTIFY");

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	if (le->notify.slot || (slot = alloc_slot(dmconfig_notify_cb, le)) == -1)
		return RC_ERR_CANNOT_SUBSCRIBE_NOTIFY;

	le->notify.slot = slot;
	le->notify.clientSockCtx = sockCtx;

	pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking unnecessary here */
	sockCtx->notifySession = le;
	pthread_mutex_unlock(&sockCtx->lock);

	return RC_OK;
}

uint32_t
rpc_unsubscribe_notify(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req)
{
	SESSION *le;

	dm_debug(req->sessionid, "CMD: UNSUBSCRIBE NOTIFY... ");

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	if (!le->notify.slot)
		return RC_ERR_REQUIRES_NOTIFY;

	unsubscribeNotify(le);

	return RC_OK;
}

uint32_t
rpc_param_notify(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, uint32_t notify, int pcnt, dm_selector *path)
{
        char b1[128];
	SESSION *le;
	int i;

	dm_debug(req->sessionid, "CMD: %s... ", "PARAM NOTIFY");

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	if (!le->notify.slot)
		return RC_ERR_REQUIRES_NOTIFY;

	notify = notify ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

	for (i = 0; i < pcnt; i++) {
		dm_debug(req->sessionid, "CMD: %s \"%s\" (%s)", "PARAM NOTIFY", sel2str(b1, path[i]), notify == ACTIVE_NOTIFY ? "active" : "passive");

		if (dm_set_notify_by_selector(path[i], le->notify.slot, notify) != DM_OK)
			return RC_ERR_MISC;
	}

	return RC_OK;
}

uint32_t
rpc_recursive_param_notify(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, uint32_t notify, dm_selector path)
{
        char b1[128];
	SESSION *le;

	dm_debug(req->sessionid, "CMD: %s \"%s\"... ", "RECURSIVE PARAM NOTIFY", sel2str(b1, path));

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	if (!le->notify.slot)
		return RC_ERR_REQUIRES_NOTIFY;

	if (dm_set_notify_by_selector_recursive(path, le->notify.slot, notify) != DM_OK)
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_get_passive_notifications(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, DM_OBJ **answer)
{
	SESSION *le;
	struct notify_queue *queue;

	dm_debug(req->sessionid, "CMD: %s... ", "GET PASSIVE NOTIFICATIONS");

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	if (!le->notify.slot)
		return RC_ERR_REQUIRES_NOTIFY;

	queue = get_notify_queue(le->notify.slot);
	return build_notify_events(queue, PASSIVE_NOTIFY, answer);
}

uint32_t
rpc_db_addinstance(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, dm_selector path, dm_id id, DM_OBJ **answer)
{
        char b1[128];
	dm_debug(req->sessionid, "CMD: %s", "DB ADD INSTANCE");

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;


	dm_debug(req->sessionid, "CMD: %s \"%s\"", "DB ADD INSTANCE", sel2str(b1, path));
	dm_debug(req->sessionid, "CMD: %s id = 0x%hX", "DB ADD INSTANCE", id);

	if (!dm_add_instance_by_selector(path, &id))
		return RC_ERR_MISC;

	if (dm_avpgrp_add_uint16(*answer, answer, AVP_UINT16, 0, VP_TRAVELPING, id))
		return RC_ERR_ALLOC;

	return RC_OK;
}

uint32_t
rpc_db_delinstance(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, dm_selector path)
{
        char b1[128];

	/* improvised: check whether this is a table */
	dm_debug(req->sessionid, "CMD: %s \"%s\"", "DB DELETE INSTANCE", sel2str(b1, path));

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	if (!dm_del_table_by_selector(path))
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_set(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, int pvcnt, struct rpc_db_set_path_value *values)
{
	SESSION *le;
	int i, rc;

	dm_debug(req->sessionid, "CMD: %s", "DB SET");

	if (!(le = lookup_session(req->sessionid)))
		return RC_ERR_INVALID_SESSIONID;

	for (i = 0; i < pvcnt; i++) {
		if ((rc = dm_get_value_ref_by_selector_cb(values[i].path, le, &values[i].value, dmconfig_set_cb)) == DM_OOM)
			return RC_ERR_ALLOC;
		if (rc != DM_OK)
			return RC_ERR_MISC;
	}

	return RC_OK;
}

uint32_t
rpc_db_get(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, int pcnt, struct path_type *values, DM_OBJ **answer)
{
	GET_BY_SELECTOR_CB get_value;
	int i, rc;

	struct rpc_db_get_info info = {
		.answer = answer,
	};

	get_value = cfg_sessionid && req->sessionid == cfg_sessionid ? dm_cache_get_value_by_selector_cb : dm_get_value_by_selector_cb;

	for (i = 0; i < pcnt; i++) {
		char b1[128];

		dm_debug(req->sessionid, "CMD: %s \"%s\", type: %d", "DB GET", sel2str(b1, values[i].path), values[i].type);

		info.type = values[i].type;

		if ((rc = get_value(values[i].path, T_ANY, &info, dmconfig_get_cb)) == DM_OOM)
			return RC_ERR_ALLOC;
		if (rc != DM_OK)
			return RC_ERR_MISC;
	}

	return RC_OK;
}

uint32_t
rpc_db_list(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, int level, dm_selector path, DM_OBJ **answer)
{
	struct list_ctx list_ctx;

	dm_debug(req->sessionid, "CMD: %s", "DB LIST");

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	memset(&list_ctx, 0, sizeof(struct list_ctx));
	list_ctx.ctx = *answer;
	list_ctx.answer = answer;
	list_ctx.max_level = level ? : DM_SELECTOR_LEN;

	if (!dm_walk_by_selector_cb(path, level ? level + 1 : DM_SELECTOR_LEN, &list_ctx, dmconfig_list_cb))
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_retrieve_enum(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, dm_selector path, DM_OBJ **answer)
{
        char b1[128];
	uint32_t rc;

	dm_debug(req->sessionid, "CMD: %s \"%s\"", "DB RETRIEVE ENUMS", sel2str(b1, path));

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	if ((rc = dm_get_value_by_selector_cb(path, T_ENUM, answer, dmconfig_retrieve_enums_cb)) == DM_OOM)
		return RC_ERR_ALLOC;
	if (rc != DM_OK)
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_dump(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, dm_selector path, DM_OBJ **answer)
{
        char b1[128];
	char *buf;
	long tsize;
	size_t r = 0;
	FILE *tf;

	dm_debug(req->sessionid, "CMD: %s \"%s\"", "DB DUMP", sel2str(b1, path));

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	tf = tmpfile();
	if (!tf)
		return RC_ERR_MISC;

#if 0
	/* FIXME: path lookup */
	if (path && *path)
		dm_serialize_element(tf, path, S_ALL);
	else
#endif
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

	if (dm_avpgrp_add_raw(*answer, answer, AVP_STRING, 0, VP_TRAVELPING, buf, tsize))
		return RC_ERR_ALLOC;

	free(buf);
	return RC_OK;
}

/* saves running config to persistent storage */
uint32_t
rpc_db_save(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req)
{
	dm_debug(req->sessionid, "CMD: %s", "DB SAVE");

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	if (req->sessionid == cfg_sessionid && !cache_is_empty())		/* cache not empty */
		return RC_ERR_MISC;

	dm_save();
	return RC_OK;
}

/* commits cache to running config and tries to apply changes */
uint32_t
rpc_db_commit(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req)
{
	SESSION *le;

	dm_debug(req->sessionid, "CMD: %s", "DB COMMIT");

	if (!(le = lookup_session(req->sessionid)) || req->sessionid != cfg_sessionid)
		return RC_ERR_REQUIRES_CFGSESSION;

	if (cache_validate()) {
		exec_actions_pre();
		cache_apply(le->notify.slot ? : -1);
		exec_actions();
		exec_pending_notifications();
	} else
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t
rpc_db_cancel(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req)
{
	dm_debug(req->sessionid, "CMD: %s", "DB CANCEL");

	if (!cfg_sessionid || req->sessionid != cfg_sessionid)
		return RC_ERR_REQUIRES_CFGSESSION;

	cache_reset();
	return RC_OK;
}

uint32_t
rpc_db_findinstance(SOCKCONTEXT *sockCtx __attribute__((unused)), const DMC_REQUEST *req, const dm_selector path, const struct dm_bin *name, const struct dm2_avp *search, DM_OBJ **answer)
{
	uint32_t rc;
	const struct dm_table *kw;
	dm_id param;
	struct dm_instance_node *inst;
	DM_VALUE value;

	dm_debug(req->sessionid, "CMD: %s", "DB FINDINSTANCE");

	if (!req->sessionid)
		return RC_ERR_INVALID_SESSIONID;

	/* find table structure */
	if (!(kw = dm_get_object_table_by_selector(path)))
		return RC_ERR_MISC;

	if ((param = dm_get_element_id_by_name(name->data, name->size, kw)) == DM_ERR)
		return RC_ERR_MISC;

	dm_debug(req->sessionid, "CMD: %s: parameter id: %u", "DB FINDINSTANCE", param);

	dm_debug(req->sessionid, "CMD: %s: value", "DB FINDINSTANCE");
	if ((rc = dmconfig_avp2value(search, kw->table + param - 1, &value)) == DM_OOM)
		return RC_ERR_ALLOC;
	if (rc != DM_OK)
		return RC_ERR_MISC;

	inst = find_instance_by_selector(path, param, kw->table[param - 1].type, &value);
	dm_free_any_value(kw->table + param - 1, &value);
	if (!inst)
		return RC_ERR_MISC;

	dm_debug(req->sessionid, "CMD: %s: answer: %u", "DB FINDINSTANCE", inst->instance);

	if (dm_avpgrp_add_uint16(*answer, answer, AVP_UINT16, 0, VP_TRAVELPING, inst->instance))
		return RC_ERR_ALLOC;

	return RC_OK;
}
