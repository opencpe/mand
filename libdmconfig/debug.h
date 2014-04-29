/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DMCONFIG_DEBUG_H
#define __DMCONFIG_DEBUG_H

#include <stdio.h>
#include <syslog.h>
#include <errno.h>

#include "utils/logx.h"
#include "dmmsg.h"

#if defined(LIBDMCONFIG_DEBUG)
#define trace(format, ...)                                              \
        do {                                                            \
		int _errno = errno;					\
                fprintf(stderr, "%s" format "\n", __FUNCTION__, ## __VA_ARGS__); \
		errno = _errno;						\
        } while (0)
void hexdump(void *data, int len);
void dump_dm_packet(DM_PACKET *packet);

#else
#define trace(format, ...) do {} while (0)
static inline void dump_dm_packet(DM_PACKET *packet __attribute__((unused))) {}
static inline void hexdump(void *data __attribute__((unused)), int len __attribute__((unused))) {}

#endif

#endif
