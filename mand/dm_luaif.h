#ifndef __DM_LUAIF_h
#define __DM_LUAIF_h

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "dm_token.h"

DM_RESULT init_Lua_environment(void);
DM_RESULT fp_Lua_function(const char *name, int nargs);
#if 0
DM_VALUE get_Lua_function(dm_selector sel);
int set_Lua_function(dm_selector sel, DM_VALUE val);
#endif

extern lua_State *lua_environment;

#endif
