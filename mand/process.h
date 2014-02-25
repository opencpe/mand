/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _DM_PROCESS_H
#define _DM_PROCESS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

int vsystem(const char *cmd);
int vasystem(const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 1, 2)));


#endif
