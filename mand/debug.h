/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __TR_DEBUG_H
#define __TR_DEBUG_H

#include <stdio.h>
#include <syslog.h>

#include "utils/logx.h"
#include "dm_token.h"

#if defined(SDEBUG) && !defined(NDEBUG)
#define debug(format, ...)						\
	do {								\
		logx(LOG_DEBUG, "%s" format, __FUNCTION__, ## __VA_ARGS__); \
	} while (0)

#define ENTER(...) debug(": enter" __VA_ARGS__)
#define EXIT() debug(": exit, %d", __LINE__)
#define EXIT_MSG(...) debug(": exit"  __VA_ARGS__)
#else
#define debug(format, ...) do {} while (0)
#define ENTER(...) do {} while (0)
#define EXIT() do {} while (0)
#define EXIT_MSG(...) do {} while (0)
#endif

static inline char *sel2str(char *buf, const dm_selector sel) __attribute__((nonnull (2)));
char *sel2str(char *buf, const dm_selector sel)
{
	int i;
	char *p;

	*buf = '\0';

	for (p = buf, i = 0; sel[i] && i < DM_SELECTOR_LEN; i++)
		p += sprintf(p, "%d.", sel[i]);

	return buf;
}

#endif
