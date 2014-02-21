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

#ifndef __TR069_ASRES_H
#define __TR069_ASRES_H

#include <ares.h>

extern ares_channel dns_channel;

void async_resolve(void *arg, int status, int timeouts, struct hostent *host);
int tr069d_evdns_init(const struct in_addr *nameserver);

#endif
