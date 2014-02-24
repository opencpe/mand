
#ifndef __DM_LUA_H
#define __DM_LUA_H

#include <stdint.h>
#include <lua.h>

#include "../libdmconfig/codes.h"

#define L_ALLOC		"Allocation error"
#define L_MISC		"Miscellaneous error"
#define L_TYPE		"Invalid Lua type"
#define L_NUMBER	"Invalid number of parameters"
#define L_VALUE		"Invalid value for this parameter"
#define L_TABLE		"Invalid types used in table"

#define LUA_SIG(name) \
	static int l_##name(lua_State *L)

#define LCMD_ERROR(msg, ...) \
	return luaL_error(L, msg "\n",##__VA_ARGS__);
#define L_ERROR(msg, ...) \
	luaL_error(L, msg "\n",##__VA_ARGS__);

#define NAMETOFUNC(NAME) \
	{#NAME, l_##NAME}

typedef struct lua_constants {
	const char	*lua;
	uint32_t	c;
} LUA_CONSTANTS;

static inline void lua_register_constants(lua_State *L,
					  const LUA_CONSTANTS *constants);
static inline void lua_register_type_constants(lua_State *L);

static inline void
lua_register_constants(lua_State *L, const LUA_CONSTANTS *constants)
{
	while (constants->lua) {
		lua_pushinteger(L, constants->c);
		lua_setfield(L, -2, constants->lua);
		constants++;
	}
}

	/* shouldn't be an inline function but I don't want to introduce
	 * dependencies between libluadmconfig and dmd
	 */
static inline void
lua_register_type_constants(lua_State *L)
{
	static const LUA_CONSTANTS types[] = {
		{"t_bool",	AVP_BOOL},
		{"t_int32",	AVP_INT32},
		{"t_int",	AVP_INT}, /* same as above - deprecated */
		{"t_uint32",	AVP_UINT32},
		{"t_uint",	AVP_UINT}, /* same as above - deprecated */
		{"t_int64",	AVP_INT64},
		{"t_uint64",	AVP_UINT64},
		{"t_counter",	AVP_COUNTER},
		{"t_enumid",	AVP_ENUMID},
		{"t_enum",	AVP_ENUM},
		{"t_string",	AVP_STRING},
		{"t_address",	AVP_ADDRESS},
		{"t_date",	AVP_DATE},
		{"t_absticks",	AVP_ABSTICKS},
		{"t_relticks",	AVP_RELTICKS},
		{"t_path",	AVP_PATH},
		{"t_pointer",	AVP_POINTER},
		{"t_binary",	AVP_BINARY},
		{"t_unknown",	AVP_UNKNOWN},

		{"n_object",	NODE_OBJECT},	/* list result node types */
		{"n_table",	NODE_TABLE},
		{"n_parameter",	NODE_PARAMETER},

		{NULL, 0}
	};

	lua_register_constants(L, types);
}

#endif

