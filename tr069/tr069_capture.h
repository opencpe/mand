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

#ifndef __TR069_CAP_H
#define __TR069_CAP_H

#include <ev.h>

int initcap(const char *interface, unsigned int timeout, unsigned int maxkbytes, unsigned int maxpackages);
void cleancap(void);

void cap_start_watchers(EV_P);
void cap_rem_watchers(EV_P);

#endif
