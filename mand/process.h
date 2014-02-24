#ifndef _TR_PROCESS_H
#define _TR_PROCESS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

int vsystem(const char *cmd);
int vasystem(const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 1, 2)));


#endif
