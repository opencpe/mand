/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * device manager Lua interface
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <inttypes.h>
#include <sys/param.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/*
#ifndef LUA_FUNCTIONS_PATH
#define LUA_FUNCTIONS_PATH "./"
#endif
*/

#include "dmd.h"
#include "dm_deserialize.h"
#include "dm_luaif.h"
#include "dm_lua.h"
#include "dm_token.h"
#include "dm_cache.h"
#include "dm_strings.h"
#include "dm_store.h"
#include "dm_index.h"

#include "utils/binary.h"
#include "utils/logx.h"

		/* we reuse the AVP type codes */
#include "../libdmconfig/codes.h"

#define SDEBUG
#include "debug.h"

#define NAMETOCONST(NAME) \
	{#NAME, NAME}

#define TABLE_ERR() \
	luaL_argerror(L, 1, L_TABLE);

#define FUNCTIONS_EXTENSION ".lua"

				/* buffer sizes of ASCII representations of integers */
#define UINT16_DIGITS	6	/* log(2^16-1)+1 */
#define INT64_DIGITS	21	/* log(2^63-1)+2 */
#define UINT64_DIGITS	21	/* log(2^64-1)+1 */
#define TICKS_DIGITS	INT64_DIGITS

lua_State *lua_environment;

		/* headers */

static void *realloc_wrapper(void *ud __attribute__((unused)), void *p,
			     size_t osize __attribute__((unused)), size_t s);

static DM_RESULT luaif_tvpair_to_value(lua_State *L, uint32_t type,
				       const struct dm_element *elem,
				       DM_VALUE *value);
static DM_RESULT luaif_set_cb(void *data, const dm_selector sel,
			      const struct dm_element *elem,
			      struct dm_value_table *base,
			      const void *value __attribute__((unused)),
			      DM_VALUE *st);
static DM_RESULT luaif_get_cb(void *data,
			      const dm_selector sb __attribute__((unused)),
			      const struct dm_element *elem,
			      int st_type,
			      const DM_VALUE val);
static DM_RESULT luaif_retrieve_enums_cb(void *data,
					 const dm_selector sb __attribute__((unused)),
					 const struct dm_element *elem,
					 int st_type,
					 const DM_VALUE val __attribute__((unused)));
static int luaif_list_cb(void *data, CB_type type, dm_id id,
			 const struct dm_element *elem,
			 const DM_VALUE value __attribute__((unused)));

LUA_SIG(logx);

LUA_SIG(configure);
LUA_SIG(terminate);
LUA_SIG(commit);
LUA_SIG(cancel);

LUA_SIG(save);
LUA_SIG(set);
LUA_SIG(get);
LUA_SIG(retrieve_enums);
LUA_SIG(list);
LUA_SIG(add);
LUA_SIG(delete);
LUA_SIG(find);

LUA_SIG(crypt);

LUA_SIG(deserialize_file);
LUA_SIG(deserialize_directory);

		/* Lua environment auxiliary functions */

		/* logx wrapper */

LUA_SIG(logx)
{
	int		priority;
	const char	*msg;
	int		top;

	static const int cprio[] = {
		LOG_EMERG,
		LOG_ALERT,
		LOG_CRIT,
		LOG_ERR,
		LOG_WARNING,
		LOG_NOTICE,
		LOG_INFO,
		LOG_DEBUG
	};

	static const char *lprio[] = {
		"LOG_EMERG",
		"LOG_ALERT",
		"LOG_CRIT",
		"LOG_ERR",
		"LOG_WARNING",
		"LOG_NOTICE",
		"LOG_INFO",
		"LOG_DEBUG",
		NULL
	};

	top = lua_gettop(L);
	luaL_argcheck(L, top == 2, top, L_NUMBER);
	priority = cprio[luaL_checkoption(L, 1, NULL, lprio)];
	msg = luaL_checkstring(L, 2);

	logx(priority, "%s", msg);

	lua_pushinteger(L, DM_OK);
	return 1;
}

		/* configure session handling */

		/* TODO: configure session starting timeout? */

LUA_SIG(configure)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, !top, top, L_NUMBER);

#if 0
	if (getCfgSessionStatus() != CFGSESSION_INACTIVE)
		lua_pushinteger(L, DM_ERROR);
	else {
		setCfgSessionStatus(CFGSESSION_ACTIVE_LUAIF);

		lua_pushinteger(L, DM_OK);
	}
#endif

	return 1;
}

LUA_SIG(terminate)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, !top, top, L_NUMBER);

#if 0
	if (getCfgSessionStatus() != CFGSESSION_ACTIVE_LUAIF)
		lua_pushinteger(L, DM_ERROR);
	else {
		setCfgSessionStatus(CFGSESSION_INACTIVE);

		lua_pushinteger(L, DM_OK);
	}
#endif

	return 1;
}

LUA_SIG(commit)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, !top, top, L_NUMBER);

#if 0
	if (getCfgSessionStatus() != CFGSESSION_ACTIVE_LUAIF ||
	    cache_validate())
		lua_pushinteger(L, DM_ERROR);
	else {
		cache_apply(-1);

		lua_pushinteger(L, DM_OK);
	}
#endif

	return 1;
}

LUA_SIG(cancel)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, !top, top, L_NUMBER);

#if 0
	if (getCfgSessionStatus() != CFGSESSION_ACTIVE_LUAIF)
		lua_pushinteger(L, DM_ERROR);
	else {
		cache_reset();

		lua_pushinteger(L, DM_OK);
	}
#endif

	return 1;
}

		/* generic database interface - libdmconfig like */

LUA_SIG(save)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, !top, top, L_NUMBER);

#if 0
	if (getCfgSessionStatus() == CFGSESSION_ACTIVE_LUAIF &&
	    !cache_is_empty())
		lua_pushinteger(L, DM_ERROR);
	else {
		dm_save();

		lua_pushinteger(L, DM_OK);
	}
#endif

	return 1;
}

static DM_RESULT
luaif_tvpair_to_value(lua_State *L, uint32_t type,
		      const struct dm_element *elem, DM_VALUE *value)
{
	DM_RESULT r = DM_OK;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	memset(value, 0, sizeof(DM_VALUE));

	if (type == AVP_UNKNOWN) {
		if (!lua_isstring(L, -1))
			r = DM_INVALID_TYPE;
		else {
			debug(": = %s\n", lua_tostring(L, -1));
			r = dm_string2value(elem, lua_tostring(L, -1), 0, value);
		}
	} else {
		switch (elem->type) {
		case T_STR:
			if (type != AVP_STRING || !lua_isstring(L, -1))
				r = DM_INVALID_TYPE;
			else {
				debug(": = \"%s\"\n", lua_tostring(L, -1));
				r = dm_set_string_value(value,
							   lua_tostring(L, -1));
			}

			break;

		case T_BINARY:
		case T_BASE64:
			if (type != AVP_BINARY || !lua_isstring(L, -1))
				r = DM_INVALID_TYPE;
			else {
				void	*data;
				size_t	len;

				debug(": = binary data...\n"); /* FIXME: hex dump for instance... */
				data = (void *)lua_tolstring(L, -1, &len);
				r = dm_set_binary_data(value, len, data);
			}

			break;

		case T_SELECTOR:
			if (type != AVP_PATH || !lua_isstring(L, -1))
				r = DM_INVALID_TYPE;
			else {
				const char	*path = lua_tostring(L, -1);
				dm_selector	sel;

				debug(": = \"%s\"\n", path);

				if (*path) {
					if (!dm_name2sel(path, &sel)) {
						r = DM_INVALID_VALUE;
						break;
					}
				} else
					memset(&sel, 0, sizeof(dm_selector));

				r = dm_set_selector_value(value, sel);
			}

			break;

		case T_IPADDR4: {
			struct in_addr addr;

			if (type != AVP_ADDRESS || !lua_isstring(L, -1))
				r = DM_INVALID_TYPE;
			else if (!inet_pton(AF_INET, lua_tostring(L, -1), &addr))
				r = DM_INVALID_VALUE;
			else {
				debug(": = %s\n", lua_tostring(L, -1));

				set_DM_IP4(*value, addr);
			}

			break;
		}

		case T_IPADDR6: {
			struct in6_addr addr;

			if (type != AVP_ADDRESS || !lua_isstring(L, -1))
				r = DM_INVALID_TYPE;
			else if (!inet_pton(AF_INET6, lua_tostring(L, -1), &addr))
				r = DM_INVALID_VALUE;
			else {
				debug(": = %s\n", lua_tostring(L, -1));

				set_DM_IP6(*value, addr);
			}

			break;
		}
		case T_ENUM: {
			int enumid;

			switch (type) {
			case AVP_ENUM:
				if (!lua_isstring(L, -1))
					r = DM_INVALID_TYPE;
				else if ((enumid = dm_enum2int(&elem->u.e,
								  lua_tostring(L, -1))) == -1)
					r = DM_INVALID_VALUE;
				else {
					debug(": = %s (%d)\n",
					      lua_tostring(L, -1), enumid);
					set_DM_ENUM(*value, enumid);
				}

				break;
			case AVP_ENUMID:
				if (!lua_isnumber(L, -1))
					r = DM_INVALID_TYPE;
				else {
					enumid = lua_tointeger(L, -1);
					if (enumid < 0 ||
					    enumid >= elem->u.e.cnt) {
						r = DM_INVALID_VALUE;
					} else {
						debug(": = %s (%d)\n",
						      dm_int2enum(&elem->u.e, enumid),
						      enumid);
						set_DM_ENUM(*value, enumid);
					}
				}

				break;
			default:
				r = DM_INVALID_TYPE;
			}

			break;
		}

		case T_INT:
			if (type != AVP_INT32 || !lua_isnumber(L, -1))
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT(*value, lua_tointeger(L, -1));
				debug(": = %d\n", DM_INT(*value));
			}

			break;

		case T_UINT:
			if (type != AVP_UINT32 || !lua_isnumber(L, -1))
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT(*value, lua_tointeger(L, -1));
				debug(": = %u\n", DM_UINT(*value));
			}

			break;

		case T_INT64:
			if (type != AVP_INT64) {
				r = DM_INVALID_TYPE;
				break;
			}

			switch (lua_type(L, -1)) {
			case LUA_TNUMBER:
				set_DM_INT64(*value, lua_tointeger(L, -1));
				debug(": = %" PRIi64 "\n", DM_INT64(*value));

				break;

			case LUA_TSTRING: {
				const char	*str = lua_tostring(L, -1);
				char 		*endp;
				int64_t		val;

				val = strtoll(str, &endp, 10);
				if (endp == str)
					r = DM_INVALID_VALUE;
				else {
					debug(": = %" PRIi64 "\n", val);
					set_DM_INT64(*value, val);
				}

				break;
			}
			default:
				r = DM_INVALID_TYPE;
			}

			break;

		case T_UINT64:
			if (type != AVP_UINT64) {
				r = DM_INVALID_TYPE;
				break;
			}

			switch (lua_type(L, -1)) {
			case LUA_TNUMBER:
				set_DM_UINT64(*value, lua_tointeger(L, -1));
				debug(": = %" PRIu64 "\n", DM_UINT64(*value));

				break;

			case LUA_TSTRING: {
				const char	*str = lua_tostring(L, -1);
				char 		*endp;
				uint64_t	val;

				val = strtoull(str, &endp, 10);
				if (endp == str)
					r = DM_INVALID_VALUE;
				else {
					debug(": = %" PRIu64 "\n", val);
					set_DM_UINT64(*value, val);
				}

				break;
			}
			default:
				r = DM_INVALID_TYPE;
			}

			break;

		case T_BOOL:
			if (type != AVP_BOOL || !lua_isboolean(L, -1))
				r = DM_INVALID_TYPE;
			else {
				set_DM_BOOL(*value, lua_toboolean(L, -1));
				debug(": = %d\n", DM_BOOL(*value));
			}

			break;

		case T_DATE:
			if (type != AVP_DATE || !lua_isnumber(L, -1))
				r = DM_INVALID_TYPE;
			else {
				set_DM_TIME(*value, lua_tointeger(L, -1));	/* FIXME: check whether conversion necessary */
				debug(": = (%d) %s", (int)DM_TIME(*value),
				      ctime(DM_TIME_REF(*value)));
			}

			break;

		case T_TICKS:
			switch (type) {
			case AVP_ABSTICKS: /* FIXME: convert value first */
			case AVP_RELTICKS:
				switch (lua_type(L, -1)) {
				case LUA_TNUMBER:
					set_DM_TICKS(*value, lua_tointeger(L, -1));
					debug(": = %" PRItick "\n", DM_TICKS(*value));

					break;

				case LUA_TSTRING: {
					const char	*str = lua_tostring(L, -1);
					char 		*endp;
					ticks_t		val;

					val = strtoll(str, &endp, 10);
					if (endp == str)
						r = DM_INVALID_VALUE;
					else {
						debug(": = %" PRItick "\n", val);
						set_DM_TICKS(*value, val);
					}

					break;
				}
				default:
					r = DM_INVALID_TYPE;
				}

				break;
			default:
				r = DM_INVALID_TYPE;
			}

			break;

		default:	/* includes T_COUNTER which is non-writable */
			r = DM_INVALID_TYPE;
		}
	}

	return r;
}

static DM_RESULT
luaif_set_cb(void *data, const dm_selector sel __attribute__((unused)),
	     const struct dm_element *elem,
	     struct dm_value_table *base __attribute__((unused)),
	     const void *value __attribute__((unused)), DM_VALUE *st __attribute__((unused)))
{
	lua_State	*L = data;
	DM_VALUE	new_value;
	DM_RESULT	r;

	if ((r = luaif_tvpair_to_value(L, lua_tointeger(L, -3), elem, &new_value)) != DM_OK)
		return r;

#if 0
	if (getCfgSessionStatus() == CFGSESSION_ACTIVE_LUAIF) {
		st->flags |= DV_UPDATE_PENDING;
		DM_parity_update(*st);
		cache_add(sel, "", elem, base, st, new_value, 0, NULL);
	} else {
		new_value.flags |= DV_UPDATED;
		DM_parity_update(new_value);
		r = dm_overwrite_any_value_by_selector(sel, elem->type,
							  new_value, -1);
	}
#endif

	return r;
}

LUA_SIG(set)
{
	int top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	luaL_argcheck(L, lua_istable(L, 1), 1, L_TYPE);

	lua_pushinteger(L, 1);			/* get one set group table */
	lua_gettable(L, -2);

	if (lua_isnil(L, -1))
		TABLE_ERR();

	for (int i = 2; !lua_isnil(L, -1); i++) {
		dm_selector	sel;
		DM_RESULT	rc;

		if (!lua_istable(L, -1))
			TABLE_ERR();

		for (int j = 1; j <= 3; j++) {	/* get all three parts of the group */
			lua_pushinteger(L, j);
			lua_gettable(L, -1*j-1);
		}

		if (!lua_isnumber(L, -3) || !lua_isstring(L, -2))
			TABLE_ERR();

		if (!dm_name2sel(lua_tostring(L, -2), &sel)) {
			lua_pushinteger(L, DM_VALUE_NOT_FOUND);
			return 1;
		}

		debug(": LUAIF: set %s = \n", lua_tostring(L, -2));

		if ((rc = dm_get_value_ref_by_selector_cb(sel, &sel /* ...tweak... */,
							     L, luaif_set_cb)) != DM_OK) {
			lua_pushinteger(L, rc);
			return 1;
		}

		lua_pop(L, 4);			/* removes the three group components and the table itself */

		lua_pushinteger(L, i);		/* get another set group table */
		lua_gettable(L, -2);
	}

	lua_pushinteger(L, DM_OK);
	return 1;
}

static DM_RESULT
luaif_get_cb(void *data, const dm_selector sb __attribute__((unused)),
	     const struct dm_element *elem, int st_type __attribute__((unused)), const DM_VALUE val)
{
	lua_State	*L = data;
	int 		type = lua_tointeger(L, -4);

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	switch (elem->type) {
	case T_ENUM:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_ENUM;
			/* fallthrough */
		case AVP_ENUM:
			lua_pushstring(L, dm_int2enum(&elem->u.e,
						   	 DM_ENUM(val)));

			debug(": %s (%d)\n", lua_tostring(L, -1), DM_ENUM(val));

			break;
		case AVP_ENUMID:
			lua_pushinteger(L, DM_ENUM(val));

			debug(": %s (%d)\n",
			      dm_int2enum(&elem->u.e, DM_ENUM(val)),
			      DM_ENUM(val));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_COUNTER:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_COUNTER;
			/* fallthrough */
		case AVP_COUNTER:
			lua_pushinteger(L, DM_UINT(val));

			debug(": %u\n", DM_UINT(val));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_INT:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_INT32;
			/* fallthrough */
		case AVP_INT32:
			lua_pushinteger(L, DM_INT(val));

			debug(": %d\n", DM_INT(val));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_UINT:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_UINT32;
			/* fallthrough */
		case AVP_UINT32:
			lua_pushinteger(L, DM_UINT(val));

			debug(": %u\n", DM_UINT(val));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_INT64:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_INT64;
			/* fallthrough */
		case AVP_INT64: {
			char buf[INT64_DIGITS];

			snprintf(buf, sizeof(buf), "%" PRIi64, DM_INT64(val));
			lua_pushstring(L, buf);

			debug(": %s\n", buf);

			break;
		}
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_UINT64:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_UINT64;
			/* fallthrough */
		case AVP_UINT64: {
			char buf[UINT64_DIGITS];

			snprintf(buf, sizeof(buf), "%" PRIu64, DM_UINT64(val));
			lua_pushstring(L, buf);

			debug(": %s\n", buf);

			break;
		}
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_STR:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_STRING;
			/* fallthrough */
		case AVP_STRING:
			lua_pushstring(L, DM_STRING(val) ? : "");

			debug(": \"%s\"\n", DM_STRING(val) ? : "");

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_BINARY:
	case T_BASE64:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_BINARY;
			/* fallthrough */
		case AVP_BINARY:
			if (DM_BINARY(val))
				lua_pushlstring(L, (const char *)DM_BINARY(val)->data, DM_BINARY(val)->len);
			else
				lua_pushstring(L, "");

			debug(": binary data\n"); /* FIXME */

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_IPADDR4: {
		char buf[INET6_ADDRSTRLEN];

		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_ADDRESS;
			/* fallthrough */
		case AVP_ADDRESS:
			inet_ntop(AF_INET, DM_IP4_REF(val), buf, sizeof(buf));
			lua_pushstring(L, buf);

			debug(": %s\n", lua_tostring(L, -1));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;
	}

	case T_IPADDR6: {
		char buf[INET6_ADDRSTRLEN];

		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_ADDRESS;
			/* fallthrough */
		case AVP_ADDRESS:
			inet_ntop(AF_INET6, DM_IP6_REF(val), buf, sizeof(buf));
			lua_pushstring(L, buf);

			debug(": %s\n", lua_tostring(L, -1));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;
	}

	case T_BOOL:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_BOOL;
			/* fallthrough */
		case AVP_BOOL:
			lua_pushboolean(L, DM_BOOL(val));

			debug(": %s (%d)\n", DM_BOOL(val) ? "true" : "false",
			      DM_BOOL(val));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_DATE:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_DATE;
			/* fallthrough */
		case AVP_DATE:
			lua_pushinteger(L, DM_TIME(val));

			debug(": (%d) %s",
			      (int)DM_TIME(val), ctime(DM_TIME_REF(val)));

			break;
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_TICKS:
		if (type == AVP_UNKNOWN)
			type = elem->flags & F_DATETIME ? AVP_ABSTICKS
							: AVP_RELTICKS;

		switch (type) {
		case AVP_ABSTICKS:
		case AVP_RELTICKS: {
			char buf[TICKS_DIGITS];

			snprintf(buf, sizeof(buf), "%" PRItick,
				 type == AVP_ABSTICKS ? ticks2realtime(DM_TICKS(val))
						      : DM_TICKS(val));
			lua_pushstring(L, buf);

			debug(": %s\n", buf);

			break;
		}
		default:
			return DM_INVALID_TYPE;
		}
		break;

	case T_SELECTOR:
		switch (type) {
		case AVP_UNKNOWN:
			type = AVP_PATH;
			/* fallthrough */
		case AVP_PATH: {
			char buffer[MAX_PARAM_NAME_LEN];
			char *name;

			if (!DM_SELECTOR(val))
				name = "";
			else if (!(name = dm_sel2name(*DM_SELECTOR(val),
							 buffer, sizeof(buffer))))
				return DM_INVALID_VALUE;

			lua_pushstring(L, name);

			debug(": \"%s\"\n", name);

			break;
		}
		default:
			return DM_INVALID_TYPE;
		}
		break;

	default:
		return DM_INVALID_TYPE;
	}

	lua_setfield(L, -2, "value");
	lua_pushinteger(L, type);
	lua_setfield(L, -2, "type");

	return DM_OK;
}

LUA_SIG(get)
{
	int top = lua_gettop(L);
#if 0
	GET_BY_SELECTOR_CB get_value = getCfgSessionStatus() == CFGSESSION_ACTIVE_LUAIF ?
					dm_cache_get_value_by_selector_cb :
					dm_get_value_by_selector_cb;
#else
	GET_BY_SELECTOR_CB get_value = dm_get_value_by_selector_cb;
#endif

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	luaL_argcheck(L, lua_istable(L, 1), 1, L_TYPE);

	lua_newtable(L);			/* result table */
	lua_insert(L, 1);			/* pull parameter table */

	lua_pushinteger(L, 1);			/* get one get group table */
	lua_gettable(L, -2);

	if (lua_isnil(L, -1))
		TABLE_ERR();

	for (int i = 2; !lua_isnil(L, -1); i++) {
		dm_selector	sel;
		DM_RESULT	rc;

		if (!lua_istable(L, -1))
			TABLE_ERR();

		for (int j = 1; j <= 2; j++) {	/* get all two parts of the group */
			lua_pushinteger(L, j);
			lua_gettable(L, -1*j-1);
		}

		if (!lua_isnumber(L, -2) || !lua_isstring(L, -1))
			TABLE_ERR();

		if (!dm_name2sel(lua_tostring(L, -1), &sel)) {
			lua_pushinteger(L, DM_VALUE_NOT_FOUND);
			return 1;
		}

		debug(": LUAIF: get %s => \n", lua_tostring(L, -1));

		lua_pushinteger(L, i - 1);
		lua_createtable(L, 0, 2);

		if ((rc = get_value(sel, T_ANY, L, luaif_get_cb)) != DM_OK) {
			lua_pushinteger(L, rc);
			return 1;
		}

		lua_settable(L, 1);		/* fill result table */

		lua_pop(L, 3);			/* removes the two group components and the table itself */

		lua_pushinteger(L, i);		/* get another get group table */
		lua_gettable(L, -2);
	}

	lua_pop(L, 2);				/* pop nil & param table */

	lua_pushinteger(L, DM_OK);
	lua_insert(L, -2);

	return 2;
}

static DM_RESULT
luaif_retrieve_enums_cb(void *data,
			const dm_selector sb __attribute__((unused)),
			const struct dm_element *elem,
			int st_type __attribute__((unused)),
			const DM_VALUE val __attribute__((unused)))
{
	lua_State		*L = data;

	const struct dm_enum	*enumer;

	char			*ptr;
	int			i;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	enumer = &elem->u.e;
	for (i = 1, ptr = enumer->data; i <= enumer->cnt;
						i++, ptr += strlen(ptr) + 1) {
		lua_pushinteger(L, i);
		lua_pushstring(L, ptr);
		lua_settable(L, -3);
	}

	return DM_OK;
}

LUA_SIG(retrieve_enums)
{
	dm_selector	sel;
	const char	*path;
	DM_RESULT	rc;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	path = luaL_checkstring(L, -1);

	if (!dm_name2sel(path, &sel)) {
		lua_pushinteger(L, DM_VALUE_NOT_FOUND);
		return 1;
	}

	debug(": LUAIF: retrieve enums %s\n", path);

	lua_pushinteger(L, DM_OK);
	lua_newtable(L);

	if ((rc = dm_get_value_by_selector_cb(sel, T_ENUM, L,
						 luaif_retrieve_enums_cb)) != DM_OK) {
		lua_pushinteger(L, rc);
		return 1;
	}

	return 2;
}

/*
 * FIXME: update so it is API-compatible with dmconfig's new recursive list
 */
static int
luaif_list_cb(void *data __attribute__((unused)), CB_type type __attribute__((unused)), dm_id id __attribute__((unused)),
	      const struct dm_element *elem __attribute__((unused)),
	      const DM_VALUE value __attribute__((unused)))
{
#if 0
	lua_State	*L = data;
	int		cnt;

	uint32_t	node_type;
	char		*node_name = elem->key;
	char		numbuf[UINT16_DIGITS];

	if (!node_name)
		return 0;

	if (lua_isnil(L, -1)) {		/* hack that prevents the first element from being processed */
		lua_pop(L, 1);		/* later dm_walk_by_name might be modified or reimplemented */
		return 1;		/* see dmconfig_list_cb */
	}

	switch (type) {
	case CB_object_end:
	case CB_table_end:
	case CB_object_instance_end:
		return 1;
	case CB_object_start:
		node_type = NODE_TABLE;
		break;
	case CB_object_instance_start:
		snprintf(numbuf, sizeof(numbuf), "%hu", id);
		node_name = numbuf;
	case CB_table_start:
		node_type = NODE_OBJECT;
		break;
	case CB_element:
		node_type = NODE_PARAMETER;
		break;
	default:
		return 0;
	}

	cnt = lua_tointeger(L, -1);
	lua_newtable(L);

	lua_pushstring(L, node_name);
	lua_setfield(L, -2, "name");
	lua_pushinteger(L, node_type);
	lua_setfield(L, -2, "type");

	switch (node_type) {
	case NODE_PARAMETER: {
		uint32_t type;

		switch (elem->type) {
		case T_INT:
			type = AVP_INT32;
			break;
		case T_UINT:
			type = AVP_UINT32;
			break;
		case T_INT64:
			type = AVP_INT64;
			break;
		case T_UINT64:
			type = AVP_UINT64;
			break;
		case T_COUNTER:
			type = AVP_COUNTER;
			break;
		case T_STR:
			type = AVP_STRING;
			break;
		case T_BOOL:
			type = AVP_BOOL;
			break;
		case T_DATE:
			type = AVP_DATE;
			break;
		case T_TICKS:
			type = elem->flags & F_DATETIME ? AVP_ABSTICKS
							: AVP_RELTICKS;
			break;
		case T_SELECTOR:
			type = AVP_PATH;
			break;
		case T_ENUM:
			type = AVP_ENUM;
			break;
		case T_IPADDR4:
		case T_IPADDR6:
			type = AVP_ADDRESS;
			break;
		case T_POINTER:
			type = AVP_POINTER;
			break;
		case T_BINARY:
		case T_BASE64:
			type = AVP_BINARY;
			break;
		default:
			type = AVP_UNKNOWN;
		}

		lua_pushinteger(L, type);
		lua_setfield(L, -2, "datatype");

		break;
	}
	case NODE_OBJECT:
		lua_pushinteger(L, elem->u.t.table->size);
		lua_setfield(L, -2, "size");
	}

	lua_settable(L, -3);
	lua_pushinteger(L, cnt + 1);	/* update array index counter */

#endif
	return 1;
}

LUA_SIG(list)
{
	dm_selector	sel;
	const char	*path;
	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	path = luaL_checkstring(L, -1);

	if (!dm_name2sel(path, &sel)) {
		lua_pushinteger(L, DM_VALUE_NOT_FOUND);
		return 1;
	}

	debug(": LUAIF: list %s\n", path);

	lua_pushinteger(L, DM_OK);
	lua_newtable(L);	/* result table */
	lua_pushinteger(L, 1);	/* array index counter */

	lua_pushnil(L);		/* workaround, s.a. */

	if (!dm_walk_by_selector_cb(sel, 2, L, luaif_list_cb)) {
		lua_pushinteger(L, DM_ERROR);
		return 1;
	}

	lua_pop(L, 1);		/* remaining array counter */
	return 2;
}

LUA_SIG(add)
{
	dm_selector	sel;
	const char	*path;
	dm_id	id;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	path = luaL_checkstring(L, -1);

	if (!dm_name2sel(path, &sel)) {
		lua_pushinteger(L, DM_VALUE_NOT_FOUND);
		return 1;
	}

	debug(": LUAIF: add %s\n", path);

	id = DM_ID_USER_OBJECT;
	if (!dm_add_instance_by_selector(sel, &id)) {
		lua_pushinteger(L, DM_ERROR);
		return 1;
	}

	lua_pushinteger(L, DM_OK);
	lua_pushinteger(L, id);

	return 2;
}

LUA_SIG(delete)
{
	dm_selector	sel;
	const char	*path;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	path = luaL_checkstring(L, -1);

	if (!dm_name2sel(path, &sel)) {
		lua_pushinteger(L, DM_VALUE_NOT_FOUND);
		return 1;
	}

	debug(": LUAIF: delete %s\n", path);

	lua_pushinteger(L, dm_del_table_by_selector(sel) ? DM_OK : DM_ERROR);
	return 1;
}

LUA_SIG(find)
{
	const char			*path;
	dm_selector			sel;
	const struct dm_table	*kw;

	const char			*param;
	dm_id			paramId;

	uint32_t			type;

	DM_VALUE			value;

	struct dm_instance_node	*inst;

	int		top = lua_gettop(L);
	DM_RESULT	rc;

	luaL_argcheck(L, top == 4, top, L_NUMBER);
	path = luaL_checkstring(L, 1);
	param = luaL_checkstring(L, 2);
	type = luaL_checkinteger(L, 3);

	debug(": LUAIF: find %s, %s\n", path, param);

	if (!dm_name2sel(path, &sel)) {
		lua_pushinteger(L, DM_VALUE_NOT_FOUND);
		return 1;
	}

	if (!(kw = dm_get_object_table_by_selector(sel))) {
		lua_pushinteger(L, DM_INVALID_TYPE);
		return 1;
	}

	if ((paramId = dm_get_element_id_by_name(param, strlen(param), kw)) == DM_ERR) {
		lua_pushinteger(L, DM_VALUE_NOT_FOUND);
		return 1;
	}

	if ((rc = luaif_tvpair_to_value(L, type, kw->table + paramId - 1, &value)) != DM_OK) {
		lua_pushinteger(L, rc);
		return 1;
	}

	inst = find_instance_by_selector(sel, paramId, kw->table[paramId - 1].type, &value);
	dm_free_any_value(kw->table + paramId - 1, &value);
	if (!inst) {
		lua_pushinteger(L, DM_ERROR);
		return 1;
	}

	lua_pushinteger(L, DM_OK);
	lua_pushinteger(L, inst->instance);

	return 2;
}

		/* misc. commands (aux) */

LUA_SIG(crypt)
{
	const char	*key, *salt;
	char		*pwd;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 2, top, L_NUMBER);
	key = luaL_checkstring(L, 1);
	salt = luaL_checkstring(L, 2);

	debug(": LUAIF: crypt %s, %s\n", key, salt);

	if ((pwd = crypt(key, salt))) {
		lua_pushinteger(L, DM_OK);
		lua_pushstring(L, pwd);
		return 2;
	}

	lua_pushinteger(L, DM_ERROR);
	return 1;
}

LUA_SIG(deserialize_file)
{
	const char	*file;
	int		flags;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top && top <= 2, top, L_NUMBER);
	file = luaL_checkstring(L, 1);
	flags = (int)luaL_optinteger(L, 2, DS_USERCONFIG);

	debug(": LUAIF: deserialize_file %s, %d\n", file, flags);

	lua_pushinteger(L, dm_deserialize_file(file, flags) ? DM_ERROR : DM_OK);
	return 1;
}

LUA_SIG(deserialize_directory)
{
	const char	*dir;
	int		flags;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top && top <= 2, top, L_NUMBER);
	dir = luaL_checkstring(L, 1);
	flags = (int)luaL_optinteger(L, 2, DS_USERCONFIG);

	debug(": LUAIF: deserialize_directory %s, %d\n", dir, flags);

	lua_pushinteger(L, dm_deserialize_directory(dir, flags) ? DM_ERROR : DM_OK);
	return 1;
}

LUA_SIG(utils_encode_base64)
{
	const char	*data;
	size_t		len;
	char		*val;

	int		top = lua_gettop(L);

	luaL_argcheck(L, top == 1, top, L_NUMBER);
	data = luaL_checklstring(L, 1, &len);

	debug(": LUAIF: utils_encode_base64: %p", data);

	if (!(val = malloc(((len + 3) * 4) / 3))) {
		lua_pushinteger(L, DM_OOM);
		return 1;
	}
	dm_to64((const unsigned char*)data, len, val);

	lua_pushinteger(L, DM_OK);
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

	debug(": LUAIF: utils_decode_base64: %p", str);

	if (!(data = malloc(((strlen(str) + 4) * 3) / 4))) { /* this is going to waste some bytes.... */
		lua_pushinteger(L, DM_OOM);
		return 1;
	}
	len = dm_from64((const unsigned char *)str, data);

	lua_pushinteger(L, DM_OK);
	lua_pushlstring(L, data, len);
	free(data);

	return 2;
}

		/* internal auxiliary */

static void *
realloc_wrapper(void *ud __attribute__((unused)), void *p,
		size_t osize __attribute__((unused)), size_t s)
{
	return realloc(p, s);
}


		/* exported functions */

DM_RESULT
init_Lua_environment(void)
{
	static const struct luaL_Reg auxfuncs[] = {
		NAMETOFUNC(logx),
		NAMETOFUNC(configure),
		NAMETOFUNC(terminate),
		NAMETOFUNC(commit),
		NAMETOFUNC(cancel),
		NAMETOFUNC(save),
		NAMETOFUNC(set),
		NAMETOFUNC(get),
		NAMETOFUNC(retrieve_enums),
		NAMETOFUNC(list),
		NAMETOFUNC(add),
		NAMETOFUNC(delete),
		NAMETOFUNC(find),

		NAMETOFUNC(crypt),
		NAMETOFUNC(deserialize_file),
		NAMETOFUNC(deserialize_directory),

		NAMETOFUNC(utils_encode_base64),
		NAMETOFUNC(utils_decode_base64),
		{NULL, NULL}
	};

	static const LUA_CONSTANTS mapping[] = {
		NAMETOCONST(DM_OK),
		NAMETOCONST(DM_ERROR),
		NAMETOCONST(DM_OOM),
		NAMETOCONST(DM_INVALID_TYPE),
		NAMETOCONST(DM_INVALID_VALUE),
		NAMETOCONST(DM_VALUE_NOT_FOUND),

		NAMETOCONST(DS_BASECONFIG),
		NAMETOCONST(DS_USERCONFIG),
		NAMETOCONST(DS_VERSIONCHECK),
		{NULL, 0}
	};

	lua_State *L;

	if (!(lua_environment = lua_newstate(realloc_wrapper, NULL)))
		return DM_OOM;

	L = lua_environment;

	luaL_openlibs(L);

#if 0
	lua_getglobal(L, "require");
	lua_pushstring(L, "syslog");
	if ((r = lua_pcall(L, 1, 0, 0)) == LUA_ERRRUN) {
		debug("(): 'require \"syslog\"' error: %s\n",
		      lua_tostring(L, -1) ? : "[no error message]");
		lua_pop(L, 1);

		return DM_ERROR;
	}
	if (r) /* r == LUA_ERRMEM */
		return DM_OOM;
#endif

#if LUA_VERSION_NUM > 501
	lua_newtable(L);
	luaL_setfuncs(L, auxfuncs, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, "dm");
#else
	luaL_register(L, "dm", auxfuncs);
#endif

	lua_register_constants(L, mapping);
	lua_register_type_constants(L);		/* FIXME: maybe use types from dm_token.h */

	lua_pop(L, 1);

	return DM_OK;
}

DM_RESULT
fp_Lua_function(const char *name, int nargs)
{
	char		path[MAXPATHLEN];
	DM_RESULT	rc;
	int		r;

	lua_State	*L = lua_environment;

	if (snprintf(path, sizeof(path), "%s/%s%s",
		     LUA_FUNCTIONS_PATH, name, FUNCTIONS_EXTENSION) >= (int)sizeof(path)) {
		lua_pop(L, nargs);
		return DM_ERROR;
	}

	if ((r = luaL_loadfile(L, path))) {
		lua_pop(L, nargs);

		switch (r) {
		case LUA_ERRFILE:
			return DM_OK;
		case LUA_ERRSYNTAX:
			return DM_ERROR;
		default:
			return DM_OOM;
		}
	}
	lua_insert(L, -1 - nargs);

	if ((r = lua_pcall(L, nargs, 1, 0))) {
		debug("(): Lua function error: %s\n", lua_tostring(L, -1));
		lua_pop(L, 1);

		return r == LUA_ERRRUN ? DM_ERROR : DM_OOM;
	}

#if 0
	if (getCfgSessionStatus() == CFGSESSION_ACTIVE_LUAIF)
		setCfgSessionStatus(CFGSESSION_INACTIVE);
#endif

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return DM_OK;
	}

	if (!lua_isnumber(L, -1)) {
		lua_pop(L, 1);
		return DM_ERROR;
	}

	rc = (DM_RESULT)lua_tointeger(L, -1);
	lua_pop(L, 1);
	return rc;
}

#if 0
DM_VALUE
get_Lua_function(dm_selector sel)
{
	DM_VALUE val;

	return val;
}

int
set_Lua_function(dm_selector sel, DM_VALUE val)
{
	return 0;
}
#endif

