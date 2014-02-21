/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __TR069_EVENT_QUEUE_H
#define __TR069_EVENT_QUEUE_H

#include <stdio.h>

#include "tr069.h"
#include "soapH.h"

enum ev_cpe {
	EV_CPE_BOOTSTRAP = 0,
	EV_CPE_BOOT,
	EV_CPE_PERIODIC,
	EV_CPE_SCHEDULED,
	EV_CPE_VALUE_CHANGE,
	EV_CPE_KICKED,
	EV_CPE_CONN_REQ,
	EV_CPE_TRANS_COMPL,
	EV_CPE_DIAG_COMPL,
	EV_CPE_REQ_DOWNL,
	EV_CPE_REBOOT,
	EV_CPE_SCHED_INFORM,
	EV_CPE_DOWNLOAD,
	EV_CPE_UPLOAD
#define EV_CPE_MAX \
	EV_CPE_UPLOAD
};

void tr069_add_event(enum ev_cpe id, const char *commandKey);
int tr069_have_event(enum ev_cpe id);
void tr069_clear_event_by_type(enum ev_cpe id);
void tr069_clear_events(void);
void tr069_clear_inform_events(void);
void tr069_serialize_events(FILE *fout);
void tr069_deserialize_events(FILE *fin);

void tr069_add_events_to_inform(struct soap *soap,
				struct EventStructArray *inform_event);

#endif /* !__TR069_EVENT_QUEUE_H */
