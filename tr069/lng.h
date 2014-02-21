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

#ifndef __LNG_H
#define __LNG_H

#include "tr069_token.h"
#include "tr069_action.h"

void init_l2tpd(void);
void reconf_l2tpd(void);

int lng_ipup(const char *, const tr069_selector);
int lng_ipdown(const char *, const tr069_selector);

void dm_l2tp_reconf_action(const tr069_selector, enum dm_action_type);

#endif
