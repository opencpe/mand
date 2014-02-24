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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define SDEBUG
#include "debug.h"
#include "list.h"

#include "process.h"

int vsystem(const char *cmd)
{
	int rc = 0;
	int _errno;

	debug("(): cmd=[%s]\n", cmd);

	errno = 0;
	rc = system(cmd);

	_errno = errno;
	debug("(): cmd=[%s], rc=%d, error=%s", cmd, rc, strerror(_errno));

	return rc;
}

int vasystem(const char *fmt, ...)
{
	va_list args;
	char	buf[1024];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	return vsystem(buf);
}
