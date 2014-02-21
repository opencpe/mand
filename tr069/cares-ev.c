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

#include "config.h"

#include <assert.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/queue.h>

#include "cares-ev.h"
#include "../utils/logx.h"

#define EVCAST(type, member, var) (type *)(((unsigned char *)var) - offsetof(type, member))

int eva_usage = -1;

static void ev_idle_cb(EV_P_ ev_timer *w, int revents)
{
	struct ev_ares *ea = EVCAST(struct ev_ares, idle, w);

	logx(LOG_DEBUG, "%s: I'm idle, usage %d", __func__, eva_usage);

	if(eva_usage == 0) {
		logx(LOG_DEBUG, "%s: ea: %p, engine timed out", __func__, ea);
		ev_prepare_stop(EV_A_ &ea->prepare);
		ev_timer_stop(EV_A_ &ea->timer);
		ev_timer_stop(EV_A_ &ea->idle);
		ares_destroy(ea->channel);
		ea->channel = NULL;
		eva_usage = -1;
	}
}

static void ev_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	struct ev_ares *ea = EVCAST(struct ev_ares, timer, w);

	logx(LOG_DEBUG, "%s: ea: %p, channel: %p", __func__, ea, ea->channel);

	ares_process_fd(ea->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
}

static void ev_io_cb(EV_P_ ev_io *w, int revents)
{
	struct ev_ares *ea = (struct ev_ares *)w->data;

	logx(LOG_DEBUG, "%s: ea: %p, channel: %p, fd: %d", __func__, ea, ea->channel, w->fd);

	ev_timer_stop(EV_A_ &ea->timer);
	ares_process_fd(ea->channel,
			revents & EV_READ ? w->fd : ARES_SOCKET_BAD,
			revents & EV_WRITE ? w->fd : ARES_SOCKET_BAD);
}

static void ev_prepare_cb(EV_P_ ev_prepare *w, int revents)
{
	struct ev_ares *ea = EVCAST(struct ev_ares, prepare, w);
	struct timeval tv;

	logx(LOG_DEBUG, "%s: ea: %p", __func__, ea);

	if (!ev_is_active(&ea->timer))
		ev_timer_init(&ea->timer, ev_timeout_cb, 0, 0);

	if (ares_timeout(ea->channel, NULL, &tv)) {
		logx(LOG_DEBUG, "%s: ea: %p, channel: %p, timeout: %d.%d", __func__, ea, ea->channel, tv.tv_sec, tv.tv_usec);

		ea->timer.repeat = tv.tv_sec + tv.tv_usec * 1e-6;
		if(tv.tv_sec == 0 && tv.tv_usec == 0) {
			logx(LOG_DEBUG, "%s: ea: ares_process_fd forced", __func__);
			ares_process_fd(ea->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
		}
		ev_set_priority(&ea->timer, EV_MINPRI);
		ev_timer_again(EV_A_ &ea->timer);
	}
}

void ares_ev_sock_state_cb(void *data, int s, int rd, int wr)
{
	struct ev_ares *ea = (struct ev_ares *)data;
	struct ev_ares_io *node;
	struct ev_ares_io *w = NULL;

	ev_timer_again(EV_DEFAULT_ &ea->idle);
	logx(LOG_DEBUG, "%s: ea: %p, channel: %p, fd: %d, read: %d, write: %d", __func__, ea, ea->channel, s, rd, wr);
	TAILQ_FOREACH(node, &ea->ev_ares_io_list, ev_ares_io_list) {
		if (node->event.fd == s) {
			w = node;
			break;
		}
	}

	logx(LOG_DEBUG, "%s: w: %p", __func__, w);
	if (!w) {
		if (rd || wr) {
			w = malloc(sizeof(struct ev_ares_io));
			if (!w)
				return;

			ev_io_init(&w->event, ev_io_cb, s, 0);
			TAILQ_INSERT_TAIL(&ea->ev_ares_io_list, w, ev_ares_io_list);
		} else
			/* nothing to do */
			return;

	}

	if (ev_is_active(&w->event))
		ev_io_stop(EV_DEFAULT_ &w->event);

	if (!rd && !wr) {
		/* clear the event */
		TAILQ_REMOVE(&ea->ev_ares_io_list, w, ev_ares_io_list);
		free(w);
	} else {
		w->event.data = ea;
		ev_io_set(&w->event, s, (rd ? EV_READ : 0) | (wr ? EV_WRITE : 0));
		ev_io_start(EV_DEFAULT_ &w->event);
	}
}

void ares_init_ev(struct ev_ares *ea)
{
	memset(ea, 0, sizeof(struct ev_ares));
	TAILQ_INIT(&ea->ev_ares_io_list);
}

void ares_start_ev(struct ev_ares *ea, ares_channel channel)
{
	ea->channel = channel;

	ev_prepare_init(&ea->prepare, ev_prepare_cb);
	ev_prepare_start(EV_DEFAULT_ &ea->prepare);
	ev_timer_init (&ea->idle, ev_idle_cb, 0., 10.);
}
