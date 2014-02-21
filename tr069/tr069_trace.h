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

#ifndef __TR069_TRACE_H
#define __TR069_TRACE_H

enum tr069_trace_state {
	tr069_trace_no_reply = -1,
	tr069_trace_error,
	tr069_trace_hop,
	tr069_trace_done,
	tr069_trace_stuck,
	tr069_trace_abort
};

typedef int (*TR069_TRACE_CB)(void *ud, enum tr069_trace_state state, unsigned int hop,
			      const char *hostname, struct in_addr ip, int triptime);

#define	TRACEROUTE_STDPORT 33434

extern int		trace_running;
extern pthread_mutex_t	trace_mutex;

enum tr069_trace_state tr069_trace(struct sockaddr_in host, unsigned int tries,
				   unsigned int timeout, unsigned int blksize,
				   unsigned int mxhpcnt,
				   TR069_TRACE_CB callback, void *user_data);

#endif
