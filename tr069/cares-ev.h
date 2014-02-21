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

#ifndef __CARES_EV_H
#define __CARES_EV_H

#include <sys/queue.h>
#include <ev.h>
#include <ares.h>

extern int eva_usage;

struct ev_ares_io {
	ev_io event;

	TAILQ_ENTRY(ev_ares_io) ev_ares_io_list;
};

struct ev_ares {
	ares_channel channel;

	ev_prepare prepare;
	ev_timer timer,idle;

	TAILQ_HEAD(ev_ares_io_list, ev_ares_io) ev_ares_io_list;
};

void ares_ev_sock_state_cb(void *data, int s, int rd, int wr);
void ares_init_ev(struct ev_ares *ea);
void ares_start_ev(struct ev_ares *ea, ares_channel channel);

#endif
