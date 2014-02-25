/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __INET_HELPER_H
#define __INET_HELPER_H

#include <stdlib.h>
#include <inttypes.h>

int get_inet_ctl_socket(void);
int do_ethflags(const char *iface, uint32_t flags, uint32_t mask);
struct in_addr getifip(const char *iface);
struct in_addr getifdstip(const char *iface);

#endif
