#ifndef __LOGGING_H
#define __LOGGING_H

#include <syslog.h>
#include <netinet/ip.h>

#define LOG_EV   0x4000       /* logger called from libev callback */

extern int logx_dest;
extern int logx_level;
extern char *logx_file;

void logx_open(char *tag, int logstat, int logfac);
void logx_close(void);
void logx_remote(struct in_addr ip);
void logx(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif
