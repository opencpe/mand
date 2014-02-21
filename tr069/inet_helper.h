/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __INET_HELPER_H
#define __INET_HELPER_H

#include <stdlib.h>
#include <inttypes.h>

int get_inet_ctl_socket(void);
int do_ethflags(const char *iface, uint32_t flags, uint32_t mask);
struct in_addr getifip(const char *iface);
struct in_addr getifdstip(const char *iface);

#endif
