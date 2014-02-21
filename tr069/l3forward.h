/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __L3FORWARD_H
#define __L3FORWARD_H

#include <stdint.h>

#include "tr069_token.h"
#include "tr069_action.h"

int register_l3_policy(int, int, uint32_t, uint32_t);
int unregister_l3_policy(int, int, uint32_t, uint32_t);

void if_routes(const char *, const tr069_selector) __attribute__((nonnull (2)));

void dm_l3_reload_action(const tr069_selector, enum dm_action_type);

#endif
