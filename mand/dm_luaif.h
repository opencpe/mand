/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
