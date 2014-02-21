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

#ifndef __TR069_PING_H
#define __TR069_PING_H

#include <stdint.h>
#include <pthread.h>
#include <netinet/in.h>

typedef int (*TR069_PING_CB)(void *ud, int bytes, struct in_addr ip,
			     uint16_t seq, unsigned int triptime);

extern int		ping_running;
extern pthread_mutex_t	ping_mutex;

int tr069_ping(struct sockaddr_in host, unsigned int send_cnt, unsigned int timeout,
	       unsigned int *succ_cnt, unsigned int *fail_cnt, unsigned int *tavg,
	       unsigned int *tmin, unsigned int *tmax,
	       TR069_PING_CB callback, void *user_data);

#endif
