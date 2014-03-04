/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_DMCONFIG_H
#define __DM_DMCONFIG_H

#include <stdint.h>

#include <pthread.h>
#include <event.h>
#include <ev.h>
#include "libdmconfig/dmconfig.h"

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

typedef struct session			SESSION;
typedef struct requested_session	REQUESTED_SESSION;
typedef struct sockContext		SOCKCONTEXT;
typedef struct obj_avpinfo		OBJ_AVPINFO;
typedef struct answerInfo		ANSWERINFO;
typedef struct notify_info		NOTIFY_INFO;

typedef struct obj_group {
	uint32_t	type;
	DM_REQUEST	*req;
	DM_AVPGRP	*reqgrp;
	DM_AVPGRP	*avpgrp;
	DM_AVPGRP	*answer_grp;

	uint32_t	sessionid;
} OBJ_GROUP;

struct obj_avpinfo {
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;
};

typedef struct get_grp_container {
	uint32_t	type;
	void		*ctx;
	DM_AVPGRP	*grp;
} GET_GRP_CONTAINER;

typedef struct set_grp_container {
	OBJ_AVPINFO	*header;
	SESSION		*session;
} SET_GRP_CONTAINER;

typedef struct list_ctx {
	void		*ctx;
	DM_AVPGRP	*grp;

	int		level;
	int		max_level;
	int		firstone;
} LIST_CTX;

		/* socket specific context */

#define ANSWER_INC 16

struct answerInfo {
	DM_REQUEST *head;
	DM_REQUEST *tail;
};

struct sockContext {
	ev_async	sync; /* async watcher to trigger writeEvent resetting in the main thread */
	pthread_mutex_t	lock;

	SOCKCONTEXT	*prev;
	SOCKCONTEXT	*next;

	unsigned int	refcnt;	/* "garbage collection" reference counter */
	ev_async	free;	/* async watcher to trigger sockContext "garbage collecting" in the main thread */

	int		fd;
	COMMCONTEXT	readCtx;
	COMMCONTEXT	writeCtx;

	ANSWERINFO	send_queue;

	SESSION		*notifySession;
};

		/* session list */

struct notify_info {
	uint8_t		slot;
	SOCKCONTEXT	*clientSockCtx;
};

struct session {
	SESSION		*next;

	SOCKCONTEXT	*sockCtx;
	uint32_t	flags;
	uint32_t	sessionid;

	struct timeval	timeout_session;
	struct event	timeout;

	NOTIFY_INFO	notify;
};

		/* list of requested sessions */

struct requested_session {
	REQUESTED_SESSION	*prev;
	REQUESTED_SESSION	*next;

	uint32_t		flags;
	uint32_t		hopid;
	uint32_t		code;		/* CMD_STARTSESSION or CMD_SWITCHSESSION... */
	SOCKCONTEXT		*sockCtx;

	SESSION			*session;	/* only for switch session requests */

	struct timeval		timeout_session;

	struct event		timeout;
};

		/* access class authentication answer wrapper */

struct authentication_answer {
	uint32_t	hopid;
	SOCKCONTEXT	*sockCtx;

	struct event	timeout;
};

		/* sign of life inform answer wrapper */

struct sol_answer {
	uint32_t	hopid;
	SOCKCONTEXT	*sockCtx;
};

		/* fwupdate attributes and client info */

struct _fwupdate_ctx {
	FILE		*fwstream;
	char		*device;
	uint32_t	flags;

	SOCKCONTEXT	*sockCtx;
};

		/* ping attributes and client info */

struct _ping_ctx {
	char			*hostname;
	uint32_t		send_cnt;
	uint32_t		timeout;

	uint32_t		answer_hop2hop;
	SOCKCONTEXT		*sockCtx;

	uint8_t			abort;
	pthread_mutex_t		abort_mutex;
};

		/* traceroute attributes and client info */

struct _traceroute_ctx {
	char			*hostname;
	uint8_t			tries;
	uint32_t		timeout;
	uint16_t		size;
	uint8_t			maxhop;

	uint32_t		answer_hop2hop;
	SOCKCONTEXT		*sockCtx;

	uint8_t			abort;
	pthread_mutex_t		abort_mutex;
};

		/* packet capture attributes, process Id and client info */

struct _pcap_ctx {
	dm_selector		interface;
	char			*url;
	uint32_t		timeout;
	uint16_t		packets;
	uint16_t		kbytes;

	SOCKCONTEXT		*sockCtx;

	struct ev_loop		*loop;
	ev_async		abort;
};

		/* headers */

uint8_t init_libdmconfig_server(struct event_base *base);

void processRequestedSessions(void);

int reset_timeout_obj(uint32_t sessionid);
void dm_event_broadcast(const dm_selector sel, enum dm_action_type type);

#endif
