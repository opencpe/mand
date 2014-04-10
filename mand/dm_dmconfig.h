/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_DMCONFIG_H
#define __DM_DMCONFIG_H

#include <stdint.h>

#include <pthread.h>
#include <ev.h>
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmcontext.h"

#include "dm_token.h"
#include "dm_store.h"
#include "dm_action.h"

			/* this could be in a separate header file to avoid duplicate code (dmconfig.h) */

#define SERVER_IP		0x7F000001	/* localhost */
#define ACCEPT_IP		SERVER_IP
#define SERVER_PORT		1100
#define SERVER_LOCAL		"DMSOCKET"

#define CHUNKSIZE		2048

#define MAX_INT			0xFFFFFFFF

#define MAX_CONNECTIONS		100		/* maximum number of pending connections */

#define REBOOT_DELAY		5		/* 5 seconds */

#define RESET_FILE		"/jffs/.tpGW"

		/* auxillary data objects */

typedef struct sockContext		SOCKCONTEXT;

/* socket specific context */

struct sockContext {
	TAILQ_ENTRY(sockContext) list;

	DMCONTEXT *socket;

	ev_timer session_timer_ev;

	uint32_t id;
	uint32_t flags;
	int notify_slot;

	char *role;
};

/* headers */

extern uint32_t cfg_session_id;

uint32_t init_libdmconfig_server(struct ev_loop *base);
void dm_event_broadcast(const dm_selector sel, enum dm_action_type type);

#endif
