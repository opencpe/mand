/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <syslog.h>

#include "utils/logx.h"
#include "dm_assert.h"

void __dm_assert_fail(const char *assertion, unsigned int line, const char *function)
{
	logx(LOG_CRIT, "assertion '%s' failed at %s:%d", assertion, function, line);
	abort();
}

void __dm_type_assert_fail(const char *expected, int got, unsigned int line, const char *function)
{
	logx(LOG_CRIT, "assertion type=='%s' failed at %s:%d, got type==%X", expected, function, line, got);
	abort();
}

void __dm_parity_assert_fail(unsigned int expected, unsigned int got, unsigned int line, const char *function)
{
	logx(LOG_CRIT, "invalid parity at %s:%d, %08x != %08x", function, line, got, expected);
	abort();
}

void __dm_magic_assert_fail(const char *field, const void *ptr, unsigned int expected, unsigned int got, unsigned int line, const char *function)
{
	logx(LOG_CRIT, "invalid magic at %s:%d, %s(%p): %08x != %08x", function, line, field, ptr, got, expected);
	abort();
}
