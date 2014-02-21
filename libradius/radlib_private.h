/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libradius/radlib_private.h,v 1.6 2004/04/27 15:00:29 ru Exp $
 */

#ifndef RADLIB_PRIVATE_H
#define RADLIB_PRIVATE_H

#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <sys/queue.h>

#include <ev.h>

#include "radlib.h"
#include "radlib_compat.h"
#include "radlib_vs.h"

/* Defaults */
#define MAXTRIES		3
#define PATH_RADIUS_CONF	"/etc/radius.conf"
#define RADIUS_PORT		1812
#define RADACCT_PORT		1813
#define TIMEOUT			3	/* In seconds */

/* Limits */
#define ERRSIZE		128		/* Maximum error message length */
#define MAXCONFLINE	1024		/* Maximum config file line length */
#define MAXSERVERS	10		/* Maximum number of servers to try */
#define MSGSIZE		4096		/* Maximum RADIUS message */
#define MINMSGSIZE	20		/* Minumum length of a RADIUS message */
#define PASSSIZE	128		/* Maximum significant password chars */

/* Positions of fields in RADIUS messages */
#define POS_CODE	0		/* Message code */
#define POS_IDENT	1		/* Identifier */
#define POS_LENGTH	2		/* Message length */
#define POS_AUTH	4		/* Authenticator */
#define LEN_AUTH	16		/* Length of authenticator */
#define POS_ATTRS	20		/* Start of attributes */

typedef uint64_t timestamp;

struct rad_queue;

struct rad_packet {
	unsigned char	 packet[MSGSIZE];	/* Request to send */
	time_t	 	 request_created;	/* rad_create_request() called? */
	int		 len;			/* Length of request */
	int		 pos;			/* Current position scanning attrs */
	char		 pass[PASSSIZE];	/* Cleartext password */
	int		 pass_len;		/* Length of cleartext password */
	int		 pass_pos;		/* Position of scrambled password */
	int		 authentic_pos;		/* Position of message authenticator */
	int		 acct_delay_pos;	/* Position of Acct-Delay-Time attribute */
};

struct rad_handle {
	struct rad_setup *setup;
	struct rad_queue *queue;        /* Queue the request is currently on */
	int              id;            /* Request id in the queue */

	void		*data;		/* User data for callback*/	

	char		 errmsg[ERRSIZE];	/* Most recent error message */
	struct rad_packet request;		/* Request to send */
	struct rad_packet response;		/* Response received */

	int		 total_tries;	/* How many requests we'll send */
	int		 try;		/* How many requests we've sent */
	int		 type;		/* Handle type */

	timestamp        timeout;       /* timeout for this request */

	struct rad_server_node *server; /* Back link to the server */
	struct rad_server_node *stop_srv;
};

struct rad_queue {
	ev_io            event;
	ev_timer         timer;

	LIST_ENTRY(rad_queue) next;	/* list of request queues */
	struct rad_server *server;      /* Back link to the server */
	int		 fd;		/* Socket file descriptor */

	int              outstanding;   /* Number of currently outstanding requests */
	int              next_id;       /* Next radius request id to use */

	struct rad_handle *requests[256]; /* Array of 256 pointer to outstanding radius requests */
};

struct rad_server_node {
	uint32_t		 id;	/* external id */
	int			 ref_cnt; /* reference counting */

	TAILQ_ENTRY(rad_server_node) next; /* list of radius servers */
	struct rad_server	*server; /* pointer to the specific server */
};

struct rad_setup {
	int			 type;		/* Server type */
	rad_notify_cb		*cb;
	void			*user;

	TAILQ_HEAD(rad_server_node_list, rad_server_node) servers;
};

struct vendor_attribute {
	u_int32_t vendor_value;
	u_char attrib_type;
	u_char attrib_len;
	u_char attrib_data[1];
};

#endif
