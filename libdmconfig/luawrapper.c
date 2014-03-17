/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * libdmconfig / Lua wrapper
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
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <fcntl.h>
#include <event.h>

#include <lua.h>
#include <lauxlib.h>

#include "dmmsg.h"
#include "codes.h"
#include "dmconfig.h"

#include "mand/dm_lua.h"
#include "utils/logx.h"
#include "utils/binary.h"

typedef struct _Lua_callback {
	lua_State	*L;

	int		context_ref;
	int		callback_ref;
	int		user_data_ref;

	uint32_t	code;

	uint8_t		callbackDone;
} LUA_CALLBACK;

#define LUA_SIG_REGISTER(name)	\
	LUA_SIG(register_##name)

#define LSTD_FUNC_BOTH(FNAME, CODE)	\
	LSTD_FUNC(FNAME, CODE)		\
	LSTD_FUNC_REGISTER(FNAME, CODE)

static uint32_t Lua_decode_get_session_info(lua_State *L, DM_AVPGRP *answer);
static uint32_t Lua_decode_get_cfg_session_info(lua_State *L, uint32_t sessionid,
						uint32_t flags, struct timeval timeout);
static uint32_t Lua_decode_unknown(lua_State *L, uint32_t type,
				   void *data, size_t len);
static uint32_t Lua_decode_get(lua_State *L, DM_AVPGRP *answer);
static uint32_t Lua_decode_list(lua_State *L, DM_AVPGRP *grp, int *nodes);
static uint32_t Lua_decode_retrieve_enums(lua_State *L, DM_AVPGRP *answer);
static uint32_t Lua_decode_notifications(lua_State *L, DM2_AVPGRP *answer);

static void generic_Lua_callback(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
				 void *user_data, uint32_t answer_rc,
				 DM2_AVPGRP *answer_grp);
static void generic_Lua_connect_callback(DMCONFIG_EVENT event,
					 DMCONTEXT *dmCtx __attribute__((unused)),
					 void *userdata);
static void generic_Lua_active_notify_callback(DMCONFIG_EVENT event,
					       DMCONTEXT *dmCtx __attribute__((unused)),
					       void *userdata, DM_AVPGRP *grp);

static void Lua_init_eval(lua_State *L, char *udata, DMCONTEXT **dmCtx,
			  int *type);

static void Lua_register_eval(lua_State *L, uint32_t code, DMCONTEXT **ctx,
			      LUA_CALLBACK **cb);

static int Lua_generic_shutdown(lua_State *L, const char *udata);
static int Lua_generic_set_sessionid(lua_State *L, const char *udata);
static int Lua_generic_get_sessionid(lua_State *L, const char *udata);

static DM_AVPGRP* Lua_build_param_notify_grp(lua_State *L,
					       uint8_t *isActiveNotify);
static void Lua_encode_value(lua_State *L, uint32_t type, const char *path,
			     DM_AVPGRP **grp);
static DM_AVPGRP *Lua_build_set_grp(lua_State *L);
static DM_AVPGRP *Lua_build_get_grp(lua_State *L);

static int Lua_generic_request(lua_State *L, uint32_t code);
static int Lua_generic_register(lua_State *L, uint32_t code);

LUA_SIG(setDebugLevel);
LUA_SIG(init_sequential);
LUA_SIG(init_events);

LUA_SIG(utils_encode_base64);
LUA_SIG(utils_decode_base64);

LUA_SIG_REGISTER(connect);

#define LUA_HEADER_BOTH(name)	\
	LUA_SIG(name);		\
	LUA_SIG_REGISTER(name);

LUA_HEADER_BOTH(list)
LUA_HEADER_BOTH(retrieve_enums)
LUA_HEADER_BOTH(set_sessionid)
LUA_HEADER_BOTH(get_sessionid)
LUA_HEADER_BOTH(set)
LUA_HEADER_BOTH(get)
LUA_HEADER_BOTH(add)
LUA_HEADER_BOTH(delete)
LUA_HEADER_BOTH(find)
LUA_HEADER_BOTH(dump)
LUA_HEADER_BOTH(start)
LUA_HEADER_BOTH(switch)
LUA_HEADER_BOTH(terminate)
LUA_HEADER_BOTH(get_session_info)
LUA_HEADER_BOTH(get_cfg_session_info)
LUA_HEADER_BOTH(shutdown)
LUA_HEADER_BOTH(commit)
LUA_HEADER_BOTH(cancel)
LUA_HEADER_BOTH(save)
LUA_HEADER_BOTH(save_config)
LUA_HEADER_BOTH(restore_config)
LUA_HEADER_BOTH(subscribe)
LUA_HEADER_BOTH(recursive_param_notify)
LUA_HEADER_BOTH(param_notify)
LUA_HEADER_BOTH(get_passive_notifications)
LUA_HEADER_BOTH(unsubscribe)

#undef LUA_HEADER_BOTH

int luaopen_libluadmconfig(lua_State *L);

static int dmcontext_sequential_gc(lua_State *L);
static int dmcontext_events_gc(lua_State *L);
static int callback_gc(lua_State *L);

#define L_SESSIONID				"Invalid session ID (object property)"

#define EVENT_BASE_MT				"EVENT_BASE_MT"
#define DMCONFIG_SESSION_SEQUENTIAL_MT		"DMCONFIG.SESSION.SEQUENTIAL.MT"
#define DMCONFIG_SESSION_EVENTS_MT		"DMCONFIG.SESSION.EVENTS.MT"
#define DMCONFIG_CALLBACK_MT			"DMCONFIG.CALLBACK.MT"

static uint32_t
Lua_decode_get_session_info(lua_State *L, DM_AVPGRP *answer)
{
	uint32_t	rc;
	uint32_t	flags;

	if ((rc = dm_decode_get_session_info(answer, &flags)))
		return rc;

	lua_pushinteger(L, flags);

	return RC_OK;
}

static uint32_t
Lua_decode_get_cfg_session_info(lua_State *L, uint32_t sessionid, uint32_t flags, struct timeval timeout)
{
	char		buf[12]; /* log(2^32-1)+1 */

	snprintf(buf, sizeof(buf), "%u", sessionid);
				/* truncation shouldn't be possible */
	lua_pushstring(L, buf);

	lua_pushinteger(L, flags);
	lua_pushnumber(L, ((lua_Number)timeout.tv_usec)/1000000 + timeout.tv_sec);

	return RC_OK;
}

static uint32_t
Lua_decode_unknown(lua_State *L, uint32_t type, void *data, size_t len)
{
	uint32_t rc;

	switch (type) {
	case AVP_BINARY:
		lua_pushlstring(L, (const char *)data, len);
		break;
	default: {
		char *retval;

		if ((rc = dm_decode_unknown_as_string(type, data, len, &retval)))
			return rc;
		lua_pushstring(L, retval);
		free(retval);
	}
	}

	return RC_OK;
}

static uint32_t
Lua_decode_get(lua_State *L, DM_AVPGRP *answer)
{
	uint32_t	type, vendor_id;
	uint8_t		flags;
	void		*data;
	size_t		len;

	uint32_t	rc;

	lua_newtable(L);

	for (int i = 1;
	     !dm_avpgrp_get_avp(answer, &type, &flags, &vendor_id,
	     			  &data, &len); i++) {
		lua_pushinteger(L, i);

		lua_createtable(L, 0, 2);
		lua_pushinteger(L, type);
		lua_setfield(L, -2, "type");

		if ((rc = Lua_decode_unknown(L, type, data, len)))
			return rc;

		lua_setfield(L, -2, "value");
		lua_settable(L, -3);
	}

	return RC_OK;
}

static uint32_t
Lua_decode_list(lua_State *L, DM_AVPGRP *grp, int *nodes)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	uint32_t	rc;
	int		i;

	lua_newtable(L);

	for (i = 1;
	     !dm_avpgrp_get_avp(grp, &code, &flags, &vendor_id, &data, &len);
	     i++) {
		DM_AVPGRP	*node_container;
		uint32_t	type;

		if (code != AVP_CONTAINER || !len)
			return RC_ERR_MISC;
		lua_pushinteger(L, i);

		if (!(node_container = dm_decode_avpgrp(NULL, data, len)))
			return RC_ERR_ALLOC;
		lua_newtable(L);

		if (dm_avpgrp_get_avp(node_container, &code, &flags, &vendor_id,
					&data, &len) ||
		    code != AVP_NODE_NAME || !len) {
			dm_grp_free(node_container);
			return RC_ERR_MISC;
		}
		lua_pushlstring(L, data, len);
		lua_setfield(L, -2, "name");

		if (dm_avpgrp_get_avp(node_container, &code, &flags, &vendor_id,
					&data, &len) ||
		    code != AVP_NODE_TYPE || len != sizeof(uint32_t)) {
			dm_grp_free(node_container);
			return RC_ERR_MISC;
		}
		type = dm_get_uint32_avp(data);
		lua_pushinteger(L, type);
		lua_setfield(L, -2, "type");

		switch (type) {
		case NODE_PARAMETER:
			if (dm_avpgrp_get_avp(node_container, &code, &flags,
						&vendor_id, &data, &len)) {
				dm_grp_free(node_container);
				return RC_ERR_MISC;
			}

			if (code == AVP_NODE_DATATYPE) {
				if (len != sizeof(uint32_t)) {
					dm_grp_free(node_container);
					return RC_ERR_MISC;
				}

				lua_pushinteger(L, dm_get_uint32_avp(data));
				lua_setfield(L, -2, "datatype");
			} else {
				lua_pushinteger(L, code);
				lua_setfield(L, -2, "datatype");

				if ((rc = Lua_decode_unknown(L, code, data, len))) {
					dm_grp_free(node_container);
					return rc;
				}
				lua_setfield(L, -2, "value");
			}

			break;

		case NODE_TABLE:
		case NODE_OBJECT: {
			DM_AVPGRP	*child_grp;
			int		child_nodes;

			if (type == NODE_TABLE) {
				if (dm_avpgrp_get_avp(node_container, &code, &flags,
							&vendor_id, &data, &len))
					break;
			} else {
				if (dm_avpgrp_get_avp(node_container, &code, &flags,
							&vendor_id, &data, &len)) {
					dm_grp_free(node_container);
					return RC_ERR_MISC;
				}

				if (code == AVP_NODE_SIZE) {
					if (len != sizeof(uint32_t)) {
						dm_grp_free(node_container);
						return RC_ERR_MISC;
					}

					lua_pushinteger(L, dm_get_uint32_avp(data));
					lua_setfield(L, -2, "size");

					break;
				}
			}

			if (code != AVP_CONTAINER) {
				dm_grp_free(node_container);
				return RC_ERR_MISC;
			}

			if (!(child_grp = dm_decode_avpgrp(node_container, data, len))) {
				dm_grp_free(node_container);
				return RC_ERR_ALLOC;
			}

			if ((rc = Lua_decode_list(L, child_grp, &child_nodes))) {
				dm_grp_free(node_container);
				return rc;
			}
			lua_setfield(L, -2, "children");

			lua_pushinteger(L, child_nodes);
			lua_setfield(L, -2, "size");
		}
		}

		lua_settable(L, -3);
		dm_grp_free(node_container);
	}

	if (nodes)
		*nodes = i - 1;

	return RC_OK;
}

static uint32_t
Lua_decode_retrieve_enums(lua_State *L, DM_AVPGRP *answer)
{
	char		*val;
	uint32_t	rc;

	lua_newtable(L);

	for (int i = 1; !(rc = dm_decode_enumval(answer, &val)); i++) {
		lua_pushinteger(L, i);
		lua_pushstring(L, val);
		lua_settable(L, -3);
		free(val);
	}

	return rc == RC_ERR_MISC ? RC_OK : rc;
}

static uint32_t
Lua_decode_notifications(lua_State *L, DM2_AVPGRP *answer)
{
	uint32_t	type;
	DM2_AVPGRP	event;

	uint32_t	rc;

	lua_newtable(L);

	for (int i = 1; !(rc = dm_decode_notifications(answer, &type, &event)) &&
	     type != NOTIFY_NOTHING; i++) {
		char *path;

		lua_pushinteger(L, i);
		lua_createtable(L, 0, 2);

		lua_pushinteger(L, type);
		lua_setfield(L, -2, "type");

		switch (type) {
		case NOTIFY_PARAMETER_CHANGED: {
			uint32_t	type, vendor_id;
			void		*data;
			size_t		len;

			if ((rc = dm_decode_parameter_changed(&event, &path, &type)))
				return rc;

			lua_createtable(L, 0, 3);

			lua_pushinteger(L, type);
			lua_setfield(L, -2, "type");
			lua_pushstring(L, path);
			lua_setfield(L, -2, "path");
			free(path);

			if ((rc = dm_expect_avp(&event, &type, &vendor_id, &data, &len)) != RC_OK
			    || (rc = dm_expect_end(&event)) != RC_OK)
				return rc;
			if ((rc = Lua_decode_unknown(L, type, data, len)))
				return rc;
			lua_setfield(L, -2, "value");
			break;
		}
		case NOTIFY_INSTANCE_CREATED:
			if ((rc = dm_decode_instance_created(&event, &path)))
				return rc;

			lua_pushstring(L, path);
			free(path);
			break;

		case NOTIFY_INSTANCE_DELETED:
			if ((rc = dm_decode_instance_deleted(&event, &path)))
				return rc;

			lua_pushstring(L, path);
			free(path);
			break;

		default:
			return RC_ERR_MISC;
		}

		lua_setfield(L, -2, "info");
		lua_settable(L, -3);
	}

	return rc;
}

static void
generic_Lua_callback(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data,
		     uint32_t answer_rc, DM2_AVPGRP *answer_grp)
{
	LUA_CALLBACK	*cb = user_data;
	lua_State	*L = cb->L;

	int		top;

	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->callback_ref);
	top = lua_gettop(L);
	lua_pushnumber(L, event);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->context_ref);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->user_data_ref);
	lua_pushnumber(L, answer_rc);

	if (event == DMCONFIG_ANSWER_READY && !answer_rc)
		switch (cb->code) {
		case CMD_STARTSESSION:
			if (dm_decode_start_session(dmCtx, answer_grp))
				L_ERROR(L_ALLOC);
			break;
		case CMD_ENDSESSION:
			dm_context_set_sessionid(dmCtx, 0);
			break;
		case CMD_SESSIONINFO:
			if (Lua_decode_get_session_info(L, answer_grp))
				L_ERROR(L_MISC);
			break;
		case CMD_CFGSESSIONINFO: {
			uint32_t sessionid, flags;
			struct timeval timeout;

			if (dm_decode_get_cfg_session_info(answer_grp, &sessionid, &flags, &timeout))
				L_ERROR(L_ALLOC);

			Lua_decode_get_cfg_session_info(L, sessionid, flags, timeout);
			break;
		}
		case CMD_DB_FINDINSTANCE:
		case CMD_DB_ADDINSTANCE: {
			uint16_t instance;

			if (dm_decode_uint16(answer_grp, &instance))
				L_ERROR(L_ALLOC);
			lua_pushnumber(L, instance);
			break;
		}
		case CMD_DB_DUMP: {
			char *data;

			if (dm_decode_string(answer_grp, &data))
				L_ERROR(L_ALLOC);
			lua_pushstring(L, data);
			free(data);
			break;
		}
		case CMD_DB_GET:
			if (Lua_decode_get(L, answer_grp))
				L_ERROR(L_ALLOC);
			break;
		case CMD_DB_LIST:
			if (Lua_decode_list(L, answer_grp, NULL))
				L_ERROR(L_ALLOC);
			break;
		case CMD_DB_RETRIEVE_ENUMS:
			if (Lua_decode_retrieve_enums(L, answer_grp))
				L_ERROR(L_ALLOC);
			break;

		case CMD_GET_PASSIVE_NOTIFICATIONS:
			if (Lua_decode_notifications(L, answer_grp))
				L_ERROR(L_ALLOC);
			break;
		}

	lua_call(L, lua_gettop(L) - top, 0);

	luaL_unref(L, LUA_REGISTRYINDEX, cb->context_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->callback_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->user_data_ref);

	cb->callbackDone = 1;	/* req. will be removed from the request list */
}

static void
generic_Lua_connect_callback(DMCONFIG_EVENT event,
			     DMCONTEXT *dmCtx __attribute__((unused)),
			     void *userdata)
{
	LUA_CALLBACK	*cb = userdata;
	lua_State	*L = cb->L;

	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->callback_ref);
	lua_pushnumber(L, event);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->context_ref);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->user_data_ref);

	lua_call(L, 3, 0);

	luaL_unref(L, LUA_REGISTRYINDEX, cb->context_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->callback_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->user_data_ref);

	cb->callbackDone = 1;	/* connection event context and event will be removed */
}

static void
generic_Lua_active_notify_callback(DMCONFIG_EVENT event,
				   DMCONTEXT *dmCtx __attribute__((unused)),
				   void *userdata, DM_AVPGRP *grp)
{
	LUA_CALLBACK	*cb = userdata;
	lua_State	*L = cb->L;

	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->callback_ref);
	lua_pushnumber(L, event);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->context_ref);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->user_data_ref);
	if (Lua_decode_notifications(L, grp))
		L_ERROR(L_ALLOC)

	lua_call(L, 4, 0);

	/* active notifications can occur several times, so keep the references */
}

static void
Lua_init_eval(lua_State *L, char *udata, DMCONTEXT **dmCtx, int *type)
{
	int top;

		/* from luaevent.h - THIS COULD CHANGE */
	struct le_base {
		struct event_base* base;
		lua_State* loop_L;
	} *le_ud;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1 || top == 2, top, L_NUMBER);
	le_ud = luaL_checkudata(L, 1, EVENT_BASE_MT);
	if (top == 2) {
		*type = luaL_checkint(L, 2);
		luaL_argcheck(L, *type == AF_UNIX || *type == AF_INET, 2, L_VALUE);
	} else
		*type = AF_INET;

	if (!(*dmCtx = lua_newuserdata(L, sizeof(DMCONTEXT))))
		L_ERROR(L_ALLOC)
	luaL_getmetatable(L, udata);
	lua_setmetatable(L, -2);

	dm_context_init(*dmCtx, le_ud->base);
}

LUA_SIG(init_sequential)
{
	DMCONTEXT	*dmCtx;
	int		type;
	uint32_t	rc;

	Lua_init_eval(L, DMCONFIG_SESSION_SEQUENTIAL_MT, &dmCtx, &type);

	lua_pushinteger(L, rc = dm_init_socket(dmCtx, type));
	if (rc)
		return 1;
	lua_insert(L, -2);

	return 2;
}

LUA_SIG(init_events)
{
	DMCONTEXT	*dmCtx;
	int		type;
	uint32_t	rc;

	Lua_init_eval(L, DMCONFIG_SESSION_EVENTS_MT, &dmCtx, &type);

	lua_pushinteger(L, rc = dm_create_socket(dmCtx, type));
	if (rc)
		return 1;
	lua_insert(L, -2);

	return 2;
}

LUA_SIG(setDebugLevel)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);

	dmconfig_debug_level = luaL_checkinteger(L, 1);

	return 0;
}

static void
Lua_register_eval(lua_State *L, uint32_t code, DMCONTEXT **ctx, LUA_CALLBACK **cb)
{
	int top = lua_gettop(L);

	*ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_EVENTS_MT);
	if (lua_isfunction(L, top))
		lua_pushnil(L);
	else if (!lua_isfunction(L, top - 1)) {
		*cb = NULL;
		lua_pushnil(L);		/* replace context on stack with nil */
		lua_replace(L, 1);
		return;
	}

	if (!(*cb = lua_newuserdata(L, sizeof(LUA_CALLBACK))))
		L_ERROR(L_ALLOC);
	luaL_getmetatable(L, DMCONFIG_CALLBACK_MT);
	lua_setmetatable(L, -2);

	lua_insert(L, 1);		/* move userdata to the stack's bottom */

	(*cb)->L = L;
	(*cb)->user_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	(*cb)->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

	for (int i = lua_gettop(L); i > 2; i--)
		lua_insert(L, 2);	/* move everything (parameters) to the stack's bottom */

	(*cb)->context_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	(*cb)->code = code;
	(*cb)->callbackDone = 0;
}

LUA_SIG_REGISTER(connect)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	int		top;
	int		type;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, 0, &ctx, &cb);
	if ((top = lua_gettop(L)) == 1)
		type = AF_INET;
	else {
		luaL_argcheck(L, top == 2, top, L_NUMBER);
		type = luaL_checkint(L, 2);
		luaL_argcheck(L, type == AF_UNIX || type == AF_INET, 2, L_VALUE);
		lua_pop(L, 1);
	}

	rc = dm_register_connect_callback(ctx, type,
					  cb ? generic_Lua_connect_callback : NULL,
					  cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

static int
Lua_generic_shutdown(lua_State *L, const char *udata)
{
	DMCONTEXT	*ctx;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);

	ctx = luaL_checkudata(L, 1, udata);
	dm_shutdown_socket(ctx);
	dm_context_set_socket(ctx, -1);

	lua_pushinteger(L, RC_OK);
	return 1;
}

LUA_SIG(shutdown)
{
	return Lua_generic_shutdown(L, DMCONFIG_SESSION_SEQUENTIAL_MT);
}

LUA_SIG_REGISTER(shutdown)
{
	return Lua_generic_shutdown(L, DMCONFIG_SESSION_EVENTS_MT);
}

static int
Lua_generic_set_sessionid(lua_State *L, const char *udata)
{
	DMCONTEXT	*ctx;
	char		*endl;
	uint32_t	sessionid;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, udata);

	sessionid = strtoul(luaL_checkstring(L, 2), &endl, 10);
	if (*endl)
		return luaL_argerror(L, 2, L_VALUE);

	dm_context_set_sessionid(ctx, sessionid);
	lua_pushinteger(L, RC_OK);
	return 1;
}

LUA_SIG(set_sessionid)
{
	return Lua_generic_set_sessionid(L, DMCONFIG_SESSION_SEQUENTIAL_MT);
}

LUA_SIG_REGISTER(set_sessionid)
{
	return Lua_generic_set_sessionid(L, DMCONFIG_SESSION_EVENTS_MT);
}

static int
Lua_generic_get_sessionid(lua_State *L, const char *udata)
{
	DMCONTEXT	*ctx;
	int		top;

	char		buf[12]; /* log(2^32-1)+1 */

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, udata);

	lua_pushinteger(L, RC_OK);
	snprintf(buf, sizeof(buf), "%u", dm_context_get_sessionid(ctx));
				/* truncation shouldn't be possible */
	lua_pushstring(L, buf);

	return 2;
}

LUA_SIG(get_sessionid)
{
	return Lua_generic_get_sessionid(L, DMCONFIG_SESSION_SEQUENTIAL_MT);
}

LUA_SIG_REGISTER(get_sessionid)
{
	return Lua_generic_get_sessionid(L, DMCONFIG_SESSION_EVENTS_MT);
}

LUA_SIG(start)
{
	int		top;
	DMCONTEXT	*ctx;

	struct timeval	session, request;
	struct timeval	*p_session, *p_request;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 4, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	if (top > 1 && !lua_isnil(L, 2)) {
		session.tv_sec = (time_t)luaL_checkint(L, 2);
		session.tv_usec = 0;
		p_session = &session;
	} else
		p_session = NULL;

	if (top > 2 && !lua_isnil(L, 3)) {
		request.tv_sec = (time_t)luaL_checkint(L, 3);
		request.tv_usec = 0;
		p_request = &request;
	} else
		p_request = NULL;

				/* FIXME: flags at the end of the argument list is
				   only for backwards compatibility */
	lua_pushinteger(L, dm_send_start_session(ctx, luaL_optint(L, 4, CMD_FLAG_READWRITE),
						 p_session, p_request));

	return 1;
}

LUA_SIG_REGISTER(start)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;
	int		top;

	struct timeval	session, request;
	struct timeval	*p_session = NULL, *p_request = NULL;
	uint32_t	flags;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 6, top, L_NUMBER);
	Lua_register_eval(L, CMD_STARTSESSION, &ctx, &cb);

	if ((top = lua_gettop(L)) > 1) {
		if (!lua_isnil(L, 2)) {
			session.tv_sec = (time_t)luaL_checkint(L, 2);
			session.tv_usec = 0;
			p_session = &session;
		}
		lua_remove(L, 2);
	}

	if (top > 2) {
		if (!lua_isnil(L, 2)) {
			request.tv_sec = (time_t)luaL_checkint(L, 2);
			request.tv_usec = 0;
			p_request = &request;
		}
		lua_remove(L, 2);
	}

	if (top == 4) { /* FIXME: s.a. */
		flags = luaL_optint(L, 2, CMD_FLAG_READWRITE);
		lua_remove(L, 2);
	} else
		flags = CMD_FLAG_READWRITE;

	rc = dm_register_start_session(ctx, flags, p_session, p_request,
				       cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(switch)
{
	DMCONTEXT	*ctx;
	int		top;

	struct timeval	session, request;
	struct timeval	*p_session, *p_request;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 4, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	if (top > 1 && !lua_isnil(L, 2)) {
		session.tv_sec = (time_t)luaL_checkint(L, 2);
		session.tv_usec = 0;
		p_session = &session;
	} else
		p_session = NULL;

	if (top > 2 && !lua_isnil(L, 3)) {
		request.tv_sec = (time_t)luaL_checkint(L, 3);
		request.tv_usec = 0;
		p_request = &request;
	} else
		p_request = NULL;

				/* FIXME: s.a. */
	lua_pushinteger(L, dm_send_switch_session(ctx, luaL_optint(L, 4, CMD_FLAG_READWRITE),
						  p_session, p_request));

	return 1;
}

LUA_SIG_REGISTER(switch)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;
	int		top;

	struct timeval	session, request;
	struct timeval	*p_session = NULL, *p_request = NULL;
	uint32_t	flags;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 6, top, L_NUMBER);
	Lua_register_eval(L, CMD_SWITCHSESSION, &ctx, &cb);

	if ((top = lua_gettop(L)) > 1) {
		if (!lua_isnil(L, 2)) {
			session.tv_sec = (time_t)luaL_checkint(L, 2);
			session.tv_usec = 0;
			p_session = &session;
		}
		lua_remove(L, 2);
	}

	if (top > 2) {
		if (!lua_isnil(L, 2)) {
			request.tv_sec = (time_t)luaL_checkint(L, 2);
			request.tv_usec = 0;
			p_request = &request;
		}
		lua_remove(L, 2);
	}

	if (top == 4) { /* FIXME: s.a. */
		flags = luaL_optint(L, 2, CMD_FLAG_READWRITE);
		lua_remove(L, 2);
	} else
		flags = CMD_FLAG_READWRITE;

	rc = dm_register_switch_session(ctx, flags, p_session, p_request,
					cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(terminate)
{
	DMCONTEXT	*ctx;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	lua_pushinteger(L, dm_send_end_session(ctx));
	return 1;
}

LUA_SIG(get_session_info)
{
	DMCONTEXT	*ctx;
	DM_AVPGRP	*answer_grp;
	uint32_t	rc;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	if (!(rc = dm_generic_send_request(ctx, CMD_SESSIONINFO, NULL, &answer_grp))) {
		rc = Lua_decode_get_session_info(L, answer_grp);
		dm_grp_free(answer_grp);
	}
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	lua_insert(L, -2);	/* pull the flags */
	return 2;
}

LUA_SIG(get_cfg_session_info)
{
	DMCONTEXT	*ctx;
	uint32_t	sessionid;
	uint32_t	flags;
	struct timeval	timeout;
	uint32_t	rc;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	rc = dm_send_get_cfg_session_info(ctx, &sessionid, &flags, &timeout);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	Lua_decode_get_cfg_session_info(L, sessionid, flags, timeout);
	return 4;
}

LUA_SIG(list)
{
	DMCONTEXT	*ctx;
	const char	*path;
	uint16_t	level;

	uint32_t	rc;
	DM_AVPGRP	*answer;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2 || top == 3, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	path = luaL_checkstring(L, 2);
	level = luaL_optint(L, 3, 1);

	if (!(rc = dm_send_list(ctx, path, level, &answer))) {
		rc = Lua_decode_list(L, answer, NULL);
		dm_grp_free(answer);
	}
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	lua_insert(L, -2);	/* pull the table */
	return 2;
}

LUA_SIG_REGISTER(list)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	const char	*path;
	uint16_t	level;
	int		top, new_top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 5, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_LIST, &ctx, &cb);
	new_top = lua_gettop(L);
	luaL_argcheck(L, new_top == 2 || new_top == 3, top, L_NUMBER);
	path = luaL_checkstring(L, 2);
	level = luaL_optint(L, 3, 1);
	while (--new_top)
		lua_insert(L, 1);

	rc = dm_register_list(ctx, path, level, cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(retrieve_enums)
{
	DMCONTEXT	*ctx;
	const char	*path;

	DM_AVPGRP	*answer;

	uint32_t	rc;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	path = luaL_checkstring(L, 2);

	if (!(rc = dm_send_retrieve_enums(ctx, path, &answer))) {
		rc = Lua_decode_retrieve_enums(L, answer);
		dm_grp_free(answer);
	}
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	lua_insert(L, -2);	/* pull the table */
	return 2;
}

LUA_SIG_REGISTER(retrieve_enums)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	const char	*path;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_RETRIEVE_ENUMS, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 2, top, L_NUMBER);
	path = luaL_checkstring(L, 2);
	lua_insert(L, 1);

	rc = dm_register_retrieve_enums(ctx, path,
					cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

#define PTABLE_ERR() {			\
	dm_grp_free(grp);		\
	luaL_argerror(L, 3, L_TABLE);	\
}

static DM_AVPGRP*
Lua_build_param_notify_grp(lua_State *L, uint8_t *isActiveNotify)
{
	DM_AVPGRP *grp;

	luaL_argcheck(L, lua_isboolean(L, 2), 2, L_TYPE);
	luaL_argcheck(L, lua_istable(L, 3), 3, L_TYPE);

	*isActiveNotify = lua_toboolean(L, 2);

	if (!(grp = dm_grp_new()))
		L_ERROR(L_ALLOC)

	lua_pushinteger(L, 1);			/* get one path string */
	lua_gettable(L, -2);

	if (lua_isnil(L, -1))
		PTABLE_ERR();

	for (int i = 2; !lua_isnil(L, -1); i++) {
		if (!lua_isstring(L, -1))
			PTABLE_ERR();

		if (dm_grp_param_notify(&grp, lua_tostring(L, -1)))
			L_ERROR(L_ALLOC)

		lua_pop(L, 1);			/* removes the path string */

		lua_pushinteger(L, i);		/* get another path string */
		lua_gettable(L, -2);
	}

	lua_pop(L, 3);				/* remove everything */

	return grp;
}

LUA_SIG(param_notify)
{
	DMCONTEXT	*ctx;
	uint8_t		isActiveNotify;
	DM_AVPGRP	*grp;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 3, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	grp = Lua_build_param_notify_grp(L, &isActiveNotify);
	if (isActiveNotify) { /* FIXME: this is only for backwards compatibility */
		dm_grp_free(grp);
		return luaL_argerror(L, 2, L_TYPE);
	}

	lua_pushinteger(L, dm_send_packet_param_notify(ctx, 0, grp));
	dm_grp_free(grp);

	return 1;
}

LUA_SIG_REGISTER(param_notify)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	uint8_t		isActiveNotify;
	DM_AVPGRP	*grp;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 3 && top <= 5, top, L_NUMBER);
	Lua_register_eval(L, CMD_PARAM_NOTIFY, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 3, top, L_NUMBER);

	grp = Lua_build_param_notify_grp(L, &isActiveNotify);
	rc = dm_register_packet_param_notify(ctx, isActiveNotify, grp,
					     cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	dm_grp_free(grp);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(recursive_param_notify)
{
	DMCONTEXT	*ctx;

	const char	*path;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 3, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	luaL_argcheck(L, lua_isboolean(L, 2) && !lua_toboolean(L, 2), 2, L_TYPE); /* FIXME: this is only for backwards compatibility */
	path = luaL_checkstring(L, 3);

	lua_pushinteger(L, dm_send_recursive_param_notify(ctx, 0, path));

	return 1;
}

LUA_SIG_REGISTER(recursive_param_notify)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	uint8_t		isActiveNotify;
	const char	*path;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 3 && top <= 5, top, L_NUMBER);
	Lua_register_eval(L, CMD_RECURSIVE_PARAM_NOTIFY, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 3, top, L_NUMBER);
	luaL_argcheck(L, lua_isboolean(L, 2), 2, L_TYPE);
	isActiveNotify = lua_toboolean(L, 2);
	path = luaL_checkstring(L, 3);
	lua_insert(L, 1);
	lua_insert(L, 1);

	rc = dm_register_recursive_param_notify(ctx, isActiveNotify, path,
						cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(get_passive_notifications)
{
	DMCONTEXT	*ctx;
	DM_AVPGRP	*answer;
	uint32_t	rc;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	if (!(rc = dm_send_get_passive_notifications(ctx, &answer))) {
		rc = Lua_decode_notifications(L, answer);
		dm_grp_free(answer);
	}
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the table */

	return 2;
}

LUA_SIG_REGISTER(subscribe)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb, *active_notify_cb;
	uint32_t	rc;

	int		top, atop;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 5, top, L_NUMBER);
	Lua_register_eval(L, CMD_SUBSCRIBE_NOTIFY, &ctx, &cb);
	atop = lua_gettop(L);
	luaL_argcheck(L, atop == 2 || atop == 3, top, L_NUMBER);

	if (atop == 2)			/* Lua active notify cb user data may be omitted */
		lua_pushnil(L);

	if (!(active_notify_cb = lua_newuserdata(L, sizeof(LUA_CALLBACK))))
		L_ERROR(L_ALLOC);
	luaL_getmetatable(L, DMCONFIG_CALLBACK_MT);
	lua_setmetatable(L, -2);

	lua_insert(L, 2);		/* move userdata after the requests userdata */

	active_notify_cb->L = L;
	active_notify_cb->user_data_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	active_notify_cb->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	lua_rawgeti(L, LUA_REGISTRYINDEX, cb->context_ref); /* it's better to reference the dmcontext twice */
	active_notify_cb->context_ref = luaL_ref(L, LUA_REGISTRYINDEX);
	active_notify_cb->code = active_notify_cb->callbackDone = 0;

	rc = dm_register_subscribe_notify(ctx, generic_Lua_active_notify_callback,
					  active_notify_cb,
					  cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	lua_insert(L, -3);		/* pull userdatas */
	return 3;
}

LUA_SIG_REGISTER(unsubscribe)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb, *active_notify_cb;
	uint32_t	rc;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 3, top, L_NUMBER);
	Lua_register_eval(L, CMD_UNSUBSCRIBE_NOTIFY, &ctx, &cb);
	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);

	if (!(active_notify_cb = ctx->callbacks.active_notification.user_data)) {
		lua_pushinteger(L, RC_ERR_MISC);
		return 1;
	}

	rc = dm_register_unsubscribe_notify(ctx, cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	luaL_unref(L, LUA_REGISTRYINDEX, active_notify_cb->context_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, active_notify_cb->callback_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, active_notify_cb->user_data_ref);
	active_notify_cb->callbackDone = 1;

	return 2;
}

#define TABLE_ERR2() {			\
	dm_grp_free(*grp);		\
	luaL_argerror(L, 2, L_TABLE);	\
}

static void
Lua_encode_value(lua_State *L, uint32_t type, const char *path, DM_AVPGRP **grp)
{
	switch (type) {	/* eval the group and build the AVP group */
	case AVP_BOOL:
		if (!lua_isnumber(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_bool(grp, path, lua_tointeger(L, -1) ? 1 : 0))
			L_ERROR(L_ALLOC);
		break;
	case AVP_INT32:
		if (!lua_isnumber(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_int32(grp, path, lua_tointeger(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	case AVP_UINT32:
		if (!lua_isnumber(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_uint32(grp, path, lua_tointeger(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	case AVP_ABSTICKS:
	case AVP_RELTICKS:
	case AVP_INT64: {
		int64_t val;

		switch (lua_type(L, -1)) {
		case LUA_TNUMBER:
			val = htonll(lua_tointeger(L, -1));
			break;
		case LUA_TSTRING: {
			const char	*str = lua_tostring(L, -1);
			char 		*endp;

			val = htonll(strtoll(str, &endp, 10));
			if (endp == str)
				TABLE_ERR2();

			break;
		}
		default:
			TABLE_ERR2();
		}

		if (dm_grp_set(grp, path, type, &val, sizeof(val)))
			L_ERROR(L_ALLOC);

		break;
	}
	case AVP_UINT64: {
		uint64_t val;

		switch (lua_type(L, -1)) {
		case LUA_TNUMBER:
			val = lua_tointeger(L, -1);
			break;
		case LUA_TSTRING: {
			const char	*str = lua_tostring(L, -1);
			char 		*endp;

			val = strtoull(str, &endp, 10);
			if (endp == str)
				TABLE_ERR2();

			break;
		}
		default:
			TABLE_ERR2();
		}

		if (dm_grp_set_uint64(grp, path, val))
			L_ERROR(L_ALLOC);

		break;
	}
	case AVP_ENUM:
		if (!lua_isstring(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_enum(grp, path, lua_tostring(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	case AVP_ENUMID:
		if (!lua_isnumber(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_enumid(grp, path, lua_tointeger(L, -1)))
			L_ERROR(L_ALLOC)
		break;
	case AVP_STRING:
		if (!lua_isstring(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_string(grp, path, lua_tostring(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	case AVP_ADDRESS: {
		struct in_addr addr;

		if (!lua_isstring(L, -1) ||
		    !inet_aton(lua_tostring(L, -1), &addr))
			TABLE_ERR2();
		if (dm_grp_set_addr(grp, path, addr))
			L_ERROR(L_ALLOC);
		break;
	}
	case AVP_DATE:
		if (!lua_isnumber(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_date(grp, path, lua_tointeger(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	case AVP_PATH:
		if (!lua_isstring(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_path(grp, path, lua_tostring(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	case AVP_BINARY: {
		void	*data;
		size_t	len;

		if (!lua_isstring(L, -1))
			TABLE_ERR2();
		data = (void *)lua_tolstring(L, -1, &len);
		if (dm_grp_set_binary(grp, path, data, len))
			L_ERROR(L_ALLOC);
		break;
	}
	case AVP_UNKNOWN:
		if (!lua_isstring(L, -1))
			TABLE_ERR2();
		if (dm_grp_set_unknown(grp, path, lua_tostring(L, -1)))
			L_ERROR(L_ALLOC);
		break;
	default:
		TABLE_ERR2();
	}
}

#define TABLE_ERR() {			\
	dm_grp_free(grp);		\
	luaL_argerror(L, 2, L_TABLE);	\
}

static DM_AVPGRP*
Lua_build_set_grp(lua_State *L)
{
	DM_AVPGRP *grp;

	luaL_argcheck(L, lua_istable(L, 2), 2, L_TYPE);

	if (!(grp = dm_grp_new()))
		L_ERROR(L_ALLOC)

	lua_pushinteger(L, 1);			/* get one set group table */
	lua_gettable(L, -2);

	if (lua_isnil(L, -1))
		TABLE_ERR();

	for (int i = 2; !lua_isnil(L, -1); i++) {
		if (!lua_istable(L, -1))
			TABLE_ERR();

		for (int j = 1; j <= 3; j++) {	/* get all three parts of the group */
			lua_pushinteger(L, j);
			lua_gettable(L, -1*j-1);
		}

		if (!lua_isnumber(L, -3) || !lua_isstring(L, -2))
			TABLE_ERR()

		Lua_encode_value(L, lua_tointeger(L, -3),
				 lua_tostring(L, -2), &grp);

		lua_pop(L, 4);			/* removes the three group components and the table itself */

		lua_pushinteger(L, i);		/* get another set group table */
		lua_gettable(L, -2);
	}

	lua_pop(L, 2);				/* remove the nil and the table */

	return grp;
}

LUA_SIG(set)
{
	DMCONTEXT	*ctx;
	DM_AVPGRP	*grp;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	grp = Lua_build_set_grp(L);
	lua_pushinteger(L, dm_send_packet_set(ctx, grp));
	dm_grp_free(grp);

	return 1;
}

LUA_SIG_REGISTER(set)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	DM_AVPGRP	*grp;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_SET, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 2, top, L_NUMBER);

	grp = Lua_build_set_grp(L);
	rc = dm_register_packet_set(ctx, grp, cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	dm_grp_free(grp);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

static DM_AVPGRP*
Lua_build_get_grp(lua_State *L)
{
	DM_AVPGRP *grp;

	luaL_argcheck(L, lua_istable(L, 2), 2, L_TYPE);

	if (!(grp = dm_grp_new()))
		L_ERROR(L_ALLOC)

	lua_pushinteger(L, 1);			/* get one get group table */
	lua_gettable(L, -2);

	if (lua_isnil(L, -1))
		TABLE_ERR();

	for (int i = 2; !lua_isnil(L, -1); i++) {
		if (!lua_istable(L, -1))
			TABLE_ERR();

		for (int j = 1; j <= 2; j++) {	/* get all two parts of the group */
			lua_pushinteger(L, j);
			lua_gettable(L, -1*j-1);
		}

		if (!lua_isnumber(L, -2) || !lua_isstring(L, -1))
			TABLE_ERR();

		switch (lua_tointeger(L, -2)) {	/* only for validation purposes */
		case AVP_BOOL:
		case AVP_INT32:
		case AVP_UINT32:
		case AVP_INT64:
		case AVP_UINT64:
		case AVP_COUNTER:
		case AVP_ENUM:
		case AVP_ENUMID:
		case AVP_STRING:
		case AVP_ADDRESS:
		case AVP_DATE:
		case AVP_ABSTICKS:
		case AVP_RELTICKS:
		case AVP_PATH:
		case AVP_BINARY:
		case AVP_UNKNOWN:
			break;
		default:
			TABLE_ERR();
		}

						/* build the GET group */
		if (dm_avpgrp_add_uint32_string(NULL, &grp, AVP_TYPE_PATH, 0,
						  VP_TRAVELPING,
						  lua_tointeger(L, -2),
						  lua_tostring(L, -1)))
			L_ERROR(L_ALLOC);

		lua_pop(L, 3);			/* removes the two group components and the table itself */

		lua_pushinteger(L, i);		/* get another get group table */
		lua_gettable(L, -2);
	}

	lua_pop(L, 2);
	return grp;
}

LUA_SIG(get)
{
	DMCONTEXT	*ctx;

	DM_AVPGRP	*grp;
	DM_AVPGRP	*ret_grp;

	uint32_t	rc;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	grp = Lua_build_get_grp(L);
	if (!(rc = dm_send_packet_get(ctx, grp, &ret_grp)))
		rc = Lua_decode_get(L, ret_grp);
	dm_grp_free(grp);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	lua_insert(L, -2);	/* pull the table */
	return 2;
}

LUA_SIG_REGISTER(get)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	DM_AVPGRP	*grp;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_GET, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 2, top, L_NUMBER);

	grp = Lua_build_get_grp(L);
	rc = dm_register_packet_get(ctx, grp,
				    cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	dm_grp_free(grp);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(add)
{
	DMCONTEXT	*ctx;
	const char	*path;

	uint32_t	rc;
	uint16_t	instance;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2 || top == 3, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	path = luaL_checkstring(L, 2);
	instance = luaL_optint(L, 3, DM_ADD_INSTANCE_AUTO);

	lua_pushinteger(L, rc = dm_send_add_instance(ctx, path, &instance));
	if (rc)
		return 1;

	lua_pushinteger(L, instance);

	return 2;
}

LUA_SIG_REGISTER(add)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	const char	*path;
	uint16_t	instance;
	int		top, ltop;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 5, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_ADDINSTANCE, &ctx, &cb);
	ltop = lua_gettop(L);
	luaL_argcheck(L, ltop == 2 || ltop == 3, top, L_NUMBER);
	path = luaL_checkstring(L, 2);
	instance = luaL_optint(L, 3, DM_ADD_INSTANCE_AUTO);
	if (!lua_isnil(L, 3))
		lua_insert(L, 1);
	lua_insert(L, 1);

	rc = dm_register_add_instance(ctx, path, instance,
				      cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(delete)
{
	DMCONTEXT	*ctx;
	const char	*path;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	path = luaL_checkstring(L, 2);

	lua_pushinteger(L, dm_send_del_instance(ctx, path));

	return 1;
}

LUA_SIG_REGISTER(delete)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	const char	*path;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_DELINSTANCE, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 2, top, L_NUMBER);
	path = luaL_checkstring(L, 2);
	lua_insert(L, 1);

	rc = dm_register_del_instance(ctx, path,
				      cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(save_config)
{
	DMCONTEXT	*ctx;
	const char	*server;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	server = luaL_checkstring(L, 2);

	lua_pushinteger(L, dm_send_cmd_conf_save(ctx, server));

	return 1;
}

LUA_SIG_REGISTER(save_config)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	const char	*server;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DEV_CONF_SAVE, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 2, top, L_NUMBER);
	server = luaL_checkstring(L, 2);
	lua_insert(L, 1);

	rc = dm_register_cmd_conf_save(ctx, server,
				       cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(restore_config)
{
	DMCONTEXT	*ctx;
	const char	*server;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	server = luaL_checkstring(L, 2);

	lua_pushinteger(L, dm_send_cmd_conf_restore(ctx, server));

	return 1;
}

LUA_SIG_REGISTER(restore_config)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	const char	*server;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 2 && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DEV_CONF_RESTORE, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 2, top, L_NUMBER);
	server = luaL_checkstring(L, 2);
	lua_insert(L, 1);

	rc = dm_register_cmd_conf_save(ctx, server,
				       cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(find)
{
	DMCONTEXT	*ctx;
	const char	*path, *param;
	uint32_t	type;

	uint32_t	rc;
	int		top;
	DM_AVPGRP	*grp;
	uint16_t	instance;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 5, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	path = luaL_checkstring(L, 2);
	param = luaL_checkstring(L, 3);
	type = luaL_checkinteger(L, 4);

	if (!(grp = dm_grp_new())) {
		lua_pushinteger(L, RC_ERR_ALLOC);
		return 1;
	}
	Lua_encode_value(L, type, param, &grp);

	lua_pushinteger(L, rc = dm_send_find_instance(ctx, path, grp, &instance));
	dm_grp_free(grp);
	if (rc)
		return 1;

	lua_pushinteger(L, instance);

	return 2;
}

LUA_SIG_REGISTER(find)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	const char	*path, *param;
	uint32_t	type;

	uint32_t	rc;
	int		top;
	DM_AVPGRP	*grp;

	top = lua_gettop(L);
	luaL_argcheck(L, top >= 5 && top <= 7, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_FINDINSTANCE, &ctx, &cb);
	luaL_argcheck(L, lua_gettop(L) == 5, top, L_NUMBER);
	path = luaL_checkstring(L, 2);
	param = luaL_checkstring(L, 3);
	type = luaL_checkinteger(L, 4);

	if (!(grp = dm_grp_new())) {
		lua_pushinteger(L, RC_ERR_ALLOC);
		return 1;
	}
	Lua_encode_value(L, type, param, &grp);

	for (int i = 0; i < 4; i++)
		lua_insert(L, 1);

	rc = dm_register_find_instance(ctx, path, grp,
				       cb ? generic_Lua_callback : NULL, cb);
	dm_grp_free(grp);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;

	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

LUA_SIG(dump)
{
	DMCONTEXT	*ctx;
	const char	*path;

	uint32_t	rc;
	char		*result;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1 || top == 2, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);
	if (top == 2)
		path = luaL_checkstring(L, 2);
	else
		path = "";

	lua_pushinteger(L, rc = dm_send_cmd_dump(ctx, path, &result));
	if (rc)
		return 1;

	lua_pushstring(L, result);
	free(result);
	return 2;
}

LUA_SIG_REGISTER(dump)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	int		top, top_p;
	const char	*path;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 4, top, L_NUMBER);
	Lua_register_eval(L, CMD_DB_DUMP, &ctx, &cb);
	top_p = lua_gettop(L);
	luaL_argcheck(L, top_p == 1 || top_p == 2, top, L_NUMBER);
	if (top_p == 1)
		path = "";
	else {
		path = luaL_checkstring(L, 2);
		lua_insert(L, 1);
	}

	rc = dm_register_cmd_dump(ctx, path,
				  cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}

static int
Lua_generic_request(lua_State *L, uint32_t code)
{
	DMCONTEXT	*ctx;
	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);
	ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	lua_pushinteger(L, dm_generic_send_request(ctx, code, NULL, NULL));
	return 1;
}
#define LSTD_FUNC(FNAME, CODE)				\
	LUA_SIG(FNAME)					\
	{						\
		return Lua_generic_request(L, CODE);	\
	}

static int
Lua_generic_register(lua_State *L, uint32_t code)
{
	DMCONTEXT	*ctx;
	LUA_CALLBACK 	*cb;
	uint32_t	rc;

	int		top;

	top = lua_gettop(L);
	luaL_argcheck(L, top && top <= 3, top, L_NUMBER);
	Lua_register_eval(L, code, &ctx, &cb);
	top = lua_gettop(L);
	luaL_argcheck(L, top == 1, top, L_NUMBER);

	rc = dm_generic_register_request(ctx, code, NULL,
					 cb ? generic_Lua_callback : NULL, cb);
	lua_pushinteger(L, rc);
	if (rc)
		return 1;
	lua_insert(L, -2);	/* pull the user data */

	return 2;
}
#define LSTD_FUNC_REGISTER(FNAME, CODE)			\
	LUA_SIG_REGISTER(FNAME)				\
	{						\
		return Lua_generic_register(L, CODE);	\
	}

LSTD_FUNC_BOTH(commit, CMD_DB_COMMIT)
LSTD_FUNC_BOTH(cancel, CMD_DB_CANCEL)
LSTD_FUNC_BOTH(save, CMD_DB_SAVE)

LSTD_FUNC(subscribe, CMD_SUBSCRIBE_NOTIFY)
LSTD_FUNC(unsubscribe, CMD_UNSUBSCRIBE_NOTIFY)

LSTD_FUNC_REGISTER(terminate, CMD_ENDSESSION)
LSTD_FUNC_REGISTER(get_session_info, CMD_SESSIONINFO)
LSTD_FUNC_REGISTER(get_cfg_session_info, CMD_CFGSESSIONINFO)
LSTD_FUNC_REGISTER(get_passive_notifications, CMD_GET_PASSIVE_NOTIFICATIONS)

#undef LSTD_FUNC_REGISTER
#undef LSTD_FUNC

		/* invoked by Lua when the dmcontext userdata is collected
		   do some cleanup */
static int
dmcontext_sequential_gc(lua_State *L)
{
	DMCONTEXT *ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_SEQUENTIAL_MT);

	if (dm_context_get_socket(ctx) != -1)
		dm_shutdown_socket(ctx);
	dm_free_requests(ctx);

	return 0;
}

static int
dmcontext_events_gc(lua_State *L)
{
	DMCONTEXT *ctx = luaL_checkudata(L, 1, DMCONFIG_SESSION_EVENTS_MT);

	if (dm_context_get_socket(ctx) != -1)
		dm_shutdown_socket(ctx);
	dm_free_requests(ctx);

	return 0;
}

static int
callback_gc(lua_State *L)
{
	LUA_CALLBACK	*cb = luaL_checkudata(L, 1, DMCONFIG_CALLBACK_MT);
	/*DMCONTEXT	*dmCtx;*/

	if (cb->callbackDone)
		return 0;

	/*lua_rawgeti(L, LUA_REGISTRYINDEX, cb->context_ref);
	dmCtx = lua_touserdata(L, -1);
	if (dm_context_get_socket(dmCtx) != -1)
		dm_shutdown_socket(dmCtx);
	dm_free_requests(dmCtx);*/

	luaL_unref(L, LUA_REGISTRYINDEX, cb->context_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->callback_ref);
	luaL_unref(L, LUA_REGISTRYINDEX, cb->user_data_ref);

	return 0;
}

LUA_SIG(utils_encode_base64)
{
	const char	*data;
	size_t		len;
	char		*val;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	data = luaL_checklstring(L, 1, &len);

	if (!(val = malloc(((len + 3) * 4) / 3))) {
		lua_pushinteger(L, RC_ERR_ALLOC);
		return 1;
	}
	dm_to64((const unsigned char*)data, len, val);

	lua_pushinteger(L, RC_OK);
	lua_pushstring(L, val);
	free(val);

	return 2;
}

LUA_SIG(utils_decode_base64)
{
	const char	*str;

	void		*data;
	size_t		len;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	str = luaL_checkstring(L, 1);

	if (!(data = malloc(((strlen(str) + 4) * 3) / 4))) { /* this is going to waste some bytes.... */
		lua_pushinteger(L, RC_ERR_ALLOC);
		return 1;
	}
	len = dm_from64((const unsigned char *)str, data);

	lua_pushinteger(L, RC_OK);
	lua_pushlstring(L, data, len);
	free(data);

	return 2;
}

int
luaopen_libluadmconfig(lua_State *L)
{
	static const struct luaL_Reg dmconfig[] = {
		NAMETOFUNC(setDebugLevel),
		NAMETOFUNC(utils_encode_base64),
		NAMETOFUNC(utils_decode_base64),

		{"init",		l_init_sequential},
		{"init_sequential",	l_init_sequential},
		{"init_events",		l_init_events},

		{NULL, NULL}
	};

	static const struct luaL_Reg methods_sequential[] = {
		NAMETOFUNC(list),
		NAMETOFUNC(retrieve_enums),
		NAMETOFUNC(set_sessionid),
		NAMETOFUNC(get_sessionid),
		NAMETOFUNC(shutdown),
		NAMETOFUNC(start),
		NAMETOFUNC(switch),
		NAMETOFUNC(terminate),
		NAMETOFUNC(get_session_info),
		NAMETOFUNC(get_cfg_session_info),
		NAMETOFUNC(set),
		NAMETOFUNC(get),
		NAMETOFUNC(add),
		NAMETOFUNC(find),
		NAMETOFUNC(delete),
		NAMETOFUNC(commit),
		NAMETOFUNC(cancel),
		NAMETOFUNC(save),
		NAMETOFUNC(save_config),
		NAMETOFUNC(restore_config),
		NAMETOFUNC(dump),
		NAMETOFUNC(subscribe),
		NAMETOFUNC(unsubscribe),
		NAMETOFUNC(param_notify),
		NAMETOFUNC(recursive_param_notify),
		NAMETOFUNC(get_passive_notifications),
		{NULL, NULL}
	};

#define NAMETOFUNC_REGISTER(NAME) {#NAME, l_register_##NAME}
	static const struct luaL_Reg methods_events[] = {
		NAMETOFUNC_REGISTER(list),
		NAMETOFUNC_REGISTER(retrieve_enums),
		NAMETOFUNC_REGISTER(set_sessionid),
		NAMETOFUNC_REGISTER(get_sessionid),
		NAMETOFUNC_REGISTER(set),
		NAMETOFUNC_REGISTER(get),
		NAMETOFUNC_REGISTER(add),
		NAMETOFUNC_REGISTER(delete),
		NAMETOFUNC_REGISTER(find),
		NAMETOFUNC_REGISTER(dump),
		NAMETOFUNC_REGISTER(connect),
		NAMETOFUNC_REGISTER(start),
		NAMETOFUNC_REGISTER(switch),
		NAMETOFUNC_REGISTER(terminate),
		NAMETOFUNC_REGISTER(get_session_info),
		NAMETOFUNC_REGISTER(get_cfg_session_info),
		NAMETOFUNC_REGISTER(shutdown),
		NAMETOFUNC_REGISTER(commit),
		NAMETOFUNC_REGISTER(cancel),
		NAMETOFUNC_REGISTER(save),
		NAMETOFUNC_REGISTER(save_config),
		NAMETOFUNC_REGISTER(restore_config),
		NAMETOFUNC_REGISTER(subscribe),
		NAMETOFUNC_REGISTER(unsubscribe),
		NAMETOFUNC_REGISTER(param_notify),
		NAMETOFUNC_REGISTER(recursive_param_notify),
		NAMETOFUNC_REGISTER(get_passive_notifications),
		{NULL, NULL}
	};
#undef NAMETOFUNC_REGISTER

	static const LUA_CONSTANTS mapping[] = {
		{"s_readwrite",				CMD_FLAG_READWRITE},
		{"s_configure",				CMD_FLAG_CONFIGURE},

		{"c_add_instance_auto",			DM_ADD_INSTANCE_AUTO},

		{"r_ok",				RC_OK},
		{"r_err_connection",			RC_ERR_CONNECTION},
		{"r_err_misc",				RC_ERR_MISC},
		{"r_err_alloc",				RC_ERR_ALLOC},
		{"r_err_invalid_sessionid",		RC_ERR_INVALID_SESSIONID},
		{"r_err_requires_cfgsession",		RC_ERR_REQUIRES_CFGSESSION},
		{"r_err_cannot_open_cfgsession",	RC_ERR_CANNOT_OPEN_CFGSESSION},
		{"r_err_cannot_subscribe_notify",	RC_ERR_CANNOT_SUBSCRIBE_NOTIFY},
		{"r_err_requires_notify",		RC_ERR_REQUIRES_NOTIFY},
		{"r_err_timeout",			RC_ERR_TIMEOUT},
		{"r_err_operation_in_progress",		RC_ERR_OPERATION_IN_PROGRESS},
		{"r_err_hostname_resolution",		RC_ERR_HOSTNAME_RESOLUTION},

		{"d_error_connecting",			DMCONFIG_ERROR_CONNECTING},
		{"d_error_writing",			DMCONFIG_ERROR_WRITING},
		{"d_error_reading",			DMCONFIG_ERROR_READING},
		{"d_answer_ready",			DMCONFIG_ANSWER_READY},
		{"d_connected",				DMCONFIG_CONNECTED},

		{"e_nothing",				NOTIFY_NOTHING},
		{"e_changed",				NOTIFY_PARAMETER_CHANGED},
		{"e_created",				NOTIFY_INSTANCE_CREATED},
		{"e_deleted",				NOTIFY_INSTANCE_DELETED},

		{"af_unix",				AF_UNIX},
		{"af_inet",				AF_INET},

		{NULL, 0}
	};

	static const struct _gc_mapping {
		const char	*metatable;
		int		(*gcfunc)(lua_State *L);
	} gc_mappings[] = {
		{DMCONFIG_SESSION_SEQUENTIAL_MT,	dmcontext_sequential_gc},
		{DMCONFIG_SESSION_EVENTS_MT,		dmcontext_events_gc},
		{DMCONFIG_CALLBACK_MT,			callback_gc},
		{NULL, NULL}
	};

			/* metatables used by session contexts */

	luaL_newmetatable(L, DMCONFIG_SESSION_SEQUENTIAL_MT);
	lua_newtable(L);
	luaL_register(L, NULL, methods_sequential);
	lua_setfield(L, -2, "__index");

	luaL_newmetatable(L, DMCONFIG_SESSION_EVENTS_MT);
	lua_newtable(L);
	luaL_register(L, NULL, methods_events);
	lua_setfield(L, -2, "__index");

			/* create metatables if they don't already exist and register garbage collecting functions */

	for (const struct _gc_mapping *cur = gc_mappings; cur->metatable; cur++) {
		luaL_newmetatable(L, cur->metatable);
		lua_pushcfunction(L, cur->gcfunc);
		lua_setfield(L, -2, "__gc");
	}

			/* create module table & register dmconfig module functions */

	luaL_register(L, "dmconfig", dmconfig);

			/* dmconfig module constants */

	lua_register_constants(L, mapping);
	lua_register_type_constants(L);

        return 1;
}

