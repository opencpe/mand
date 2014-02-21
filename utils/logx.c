#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <errno.h>

#include <ev.h>

#include "logx.h"

#define LOGBUFSIZE (16 * 1024)

int logx_level = 2;
int logx_facility = LOG_DAEMON;
char *logx_tag = "syslog";

static int logx_fd = -1;
static struct sockaddr_in logx_sa = {
	.sin_family = AF_INET,
	.sin_addr = {INADDR_NONE}
};

void logx_open(char *tag, int logstat, int logfac)
{
	if (tag)
		logx_tag = tag;
	logx_facility = logfac;

	openlog(tag, logstat, logfac);
}

void logx_close()
{
	if (logx_fd != -1) {
		close(logx_fd);
		logx_fd = -1;
	}
}

void logx_remote(struct in_addr ip)
{
	logx_sa.sin_port = htons(514);
	logx_sa.sin_addr = ip;

	if (logx_sa.sin_addr.s_addr == INADDR_ANY || logx_sa.sin_addr.s_addr == INADDR_NONE)
		logx_close();
}

void logx(int level, const char *fmt, ...)
{
	int _errno = errno;
	va_list ap;
	char buf[4096];

	static int ctime_last = 0;
	static char ctime_buf[27];

	int pos = 1;
	struct timeval tv;

	if (LOG_PRI(level) > logx_level)
		return;

	if (logx_sa.sin_addr.s_addr == INADDR_ANY || logx_sa.sin_addr.s_addr == INADDR_NONE) {
		va_start(ap, fmt);
		vsyslog(LOG_PRI(level) | logx_facility, fmt, ap);
		va_end(ap);

		errno = _errno;
		return;
	}

	if (logx_fd < 0) {
		if ((logx_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
			perror("socket");
		} else
			fcntl(logx_fd, F_SETFL, O_NONBLOCK);
	}

	if (logx_fd < 0) {
		errno = _errno;
		return;
	}

	if (level & LOG_EV) {
		tv.tv_sec  = (time_t)ev_now(EV_DEFAULT);
		tv.tv_usec = (long)((ev_now(EV_DEFAULT) - (ev_tstamp)(tv.tv_sec)) * 1e6);
	} else
		gettimeofday(&tv, NULL);

	if (ctime_last != tv.tv_sec) {
		ctime_r(&tv.tv_sec, ctime_buf);
		ctime_last = tv.tv_sec;
	}

	if (LOG_FAC(level) == 0)
		level = LOG_PRI(level) | logx_facility;

        pos = snprintf(buf, sizeof(buf), "<%d>%.15s %s[%d]: ", level, &ctime_buf[4], logx_tag, getpid());
	pos += snprintf(buf + pos, sizeof(buf) - 2 - pos, "%d.%d ", (int)tv.tv_sec, (int)tv.tv_usec);

	/* restore errno for snprintf... */
	errno = _errno;

	va_start(ap, fmt);
	pos += vsnprintf(buf + pos, sizeof(buf) - 2 - pos, fmt, ap);
	va_end(ap);

	/* vsnprintf might return len > sizeof(buf) */
	if ((unsigned int)pos > sizeof(buf) - 2)
		pos = sizeof(buf) - 2;

	if (sendto(logx_fd, buf, pos, 0, (const struct sockaddr *)&logx_sa, sizeof(logx_sa)) == -1)
		perror("sendto");

	errno = _errno;
}
