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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <expat.h>

#include "list.h"
#include "tr069_request_queue.h"
#include "tr069_event_queue.h"

#define SDEBUG
#include "debug.h"

struct event_node {
	struct event_node *next;
	enum ev_cpe id;
	char commandKey[];
};

static struct {
	struct event_node	*next;
	pthread_mutex_t		mutex;
} event_head = { .next = NULL, .mutex = PTHREAD_MUTEX_INITIALIZER };

#define MAP(X) [X] = #X
static const char *id_map[] = {
	MAP(EV_CPE_BOOTSTRAP),
	MAP(EV_CPE_BOOT),
	MAP(EV_CPE_PERIODIC),
	MAP(EV_CPE_SCHEDULED),
	MAP(EV_CPE_VALUE_CHANGE),
	MAP(EV_CPE_KICKED),
	MAP(EV_CPE_CONN_REQ),
	MAP(EV_CPE_TRANS_COMPL),
	MAP(EV_CPE_DIAG_COMPL),
	MAP(EV_CPE_REQ_DOWNL),
	MAP(EV_CPE_REBOOT),
	MAP(EV_CPE_SCHED_INFORM),
	MAP(EV_CPE_DOWNLOAD),
	MAP(EV_CPE_UPLOAD)
};
#undef MAP

#define EV_XML_VERSION 1

static inline int event_id_cmp(struct event_node *node, enum ev_cpe id)
{
        return INTCMP(node->id, id);
}

void tr069_add_event(enum ev_cpe id, const char *commandKey)
{
	int len = sizeof(struct event_node) + 1;
	struct event_node *ev;

	ENTER();

	pthread_mutex_lock(&event_head.mutex);
	if (id <= EV_CPE_REQ_DOWNL) { /* only one entry on these types is allowed */
		struct event_node *p;

		list_search(struct event_node, event_head, id, event_id_cmp, p);
		if (p) {
			pthread_mutex_unlock(&event_head.mutex);
			EXIT();
			return;
		}
	}

	if (commandKey)
		len += strlen(commandKey);

	ev = malloc(len);
	if (!ev) {
		pthread_mutex_unlock(&event_head.mutex);
		EXIT();
		return;
	}

	ev->id = id;
	if (commandKey)
		strcpy(ev->commandKey, commandKey);
	else
		ev->commandKey[0] = '\0';

	/* new or multi entry */
	list_append(struct event_node, event_head, ev);

	pthread_mutex_unlock(&event_head.mutex);
	EXIT();
}

int tr069_have_event(enum ev_cpe id)
{
	struct event_node *p;

	ENTER();

	pthread_mutex_lock(&event_head.mutex);
	list_search(struct event_node, event_head, id, event_id_cmp, p);
	pthread_mutex_unlock(&event_head.mutex);

	EXIT();
	return p != NULL;
}

void tr069_add_events_to_inform(struct soap *soap,
				struct EventStructArray *inform_event)
{
	const char *msgs[] = { [EV_CPE_BOOTSTRAP]    = "0 BOOTSTRAP",
			       [EV_CPE_BOOT]         = "1 BOOT",
			       [EV_CPE_PERIODIC]     = "2 PERIODIC",
			       [EV_CPE_SCHEDULED]    = "3 SCHEDULED",
			       [EV_CPE_VALUE_CHANGE] = "4 VALUE CHANGE",
			       [EV_CPE_KICKED]       = "5 KICKED",
			       [EV_CPE_CONN_REQ]     = "6 CONNECTION REQUEST",
			       [EV_CPE_TRANS_COMPL]  = "7 TRANSFER COMPLETE",
			       [EV_CPE_DIAG_COMPL]   = "8 DIAGNOSTICS COMPLETE",
			       [EV_CPE_REQ_DOWNL]    = "9 REQUEST DOWNLOAD",
			       [EV_CPE_REBOOT]       = "M Reboot",
			       [EV_CPE_SCHED_INFORM] = "M ScheduleInform",
			       [EV_CPE_DOWNLOAD]     = "M Download",
			       [EV_CPE_UPLOAD]       = "M Upload",
	};
	struct event_node *ev;

	ENTER();

	if (!event_head.next) {
		EXIT();
		return;
	}

	if (!inform_event->__ptrEventStruct)
		inform_event->__ptrEventStruct = soap_malloc(soap, 64 * sizeof(struct cwmp__EventStruct));

	if (!inform_event->__ptrEventStruct) {
		EXIT();
		return;
	}
	memset(inform_event->__ptrEventStruct, 0, 64 * sizeof(struct cwmp__EventStruct));

	pthread_mutex_lock(&event_head.mutex);
	list_foreach(struct event_node, event_head, ev) {
		debug("(): head: %p, ev: %p, n: %p", event_head.next, ev, ev->next);
		debug("(): id: %d, ck: %p", ev->id, ev->commandKey);
		if (inform_event->__size < 64) {
			inform_event->__ptrEventStruct[inform_event->__size].EventCode = soap_strdup(soap, msgs[ev->id]);
			if (ev->commandKey[0])
				inform_event->__ptrEventStruct[inform_event->__size].CommandKey = soap_strdup(soap, ev->commandKey);
			inform_event->__size++;
		}
	}
	pthread_mutex_unlock(&event_head.mutex);
	EXIT();
}

void tr069_clear_event_by_type(enum ev_cpe id)
{
	struct event_node *ev, *n;

	ENTER();
	pthread_mutex_lock(&event_head.mutex);
	list_foreach_safe(struct event_node, event_head, ev, n) {
		if (ev->id == id) {
			list_remove(struct event_node, event_head, ev);
			free(ev);
		}
	}
	pthread_mutex_unlock(&event_head.mutex);
	EXIT();
}

void tr069_clear_events(void)
{
	struct event_node *ev, *n;

	ENTER();
	pthread_mutex_lock(&event_head.mutex);
	list_foreach_safe(struct event_node, event_head, ev, n) {
		list_remove(struct event_node, event_head, ev);
		free(ev);
	}
	pthread_mutex_unlock(&event_head.mutex);
	EXIT();
}

void tr069_clear_inform_events(void)
{
	struct event_node *ev, *n;

	ENTER();
	pthread_mutex_lock(&event_head.mutex);
	list_foreach_safe(struct event_node, event_head, ev, n) {

		switch(ev->id) {

		case EV_CPE_KICKED:
		case EV_CPE_TRANS_COMPL:
		case EV_CPE_DOWNLOAD:
		case EV_CPE_REQ_DOWNL:
			break;

		default:
			list_remove(struct event_node, event_head, ev);
			free(ev);
			break;
		}
	}
	pthread_mutex_unlock(&event_head.mutex);
	EXIT();
}

void
tr069_serialize_events(FILE *fout)
{
	struct event_node *ev;

	ENTER();

	fprintf(fout, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		      "\n"
		      "<events version=\"%d\">\n",
		EV_XML_VERSION);
	pthread_mutex_lock(&event_head.mutex);

	list_foreach(struct event_node, event_head, ev) {
		switch(ev->id) {
		case EV_CPE_BOOTSTRAP:
		case EV_CPE_PERIODIC:
		case EV_CPE_SCHEDULED:
		case EV_CPE_KICKED:
		case EV_CPE_TRANS_COMPL:
		case EV_CPE_REBOOT:
		case EV_CPE_SCHED_INFORM:
		case EV_CPE_DOWNLOAD:
		case EV_CPE_UPLOAD:
			fprintf(fout, "\t<event id=\"%s\" key=\"", id_map[ev->id]);
			tr069_serialize_xml_chardata(fout, ev->commandKey);
			fprintf(fout, "\"/>\n");
			break;

		default:
			break;
		}
	}

	pthread_mutex_unlock(&event_head.mutex);
	fprintf(fout, "</events>\n");

	EXIT();
}

struct ctx {
	XML_Parser parser;
	int version;
};

#define FOREACH_ATT(ATTS, P) \
	for (const XML_Char **P = ATTS; *P; P += 2)

static void XMLCALL
startEl(void *userData, const XML_Char *name, const XML_Char **atts)
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "events")) {
		FOREACH_ATT(atts, pair) {
			if (!strcmp(pair[0], "version")) {
				state->version = strtol(pair[1], NULL, 0);
			}
		}

	} else if (!strcmp(name, "event")) {
		enum ev_cpe id = EV_CPE_MAX + 1;
		const char *key = NULL;

		FOREACH_ATT(atts, pair) {
			if (!strcmp(pair[0], "id")) {
				for (id = 0; id <= EV_CPE_MAX &&
					     strcmp(id_map[id], pair[1]); id++);
			} else if (!strcmp(pair[0], "key")) {
				key = pair[1];
			}
		}

		if (id > EV_CPE_MAX) {
			debug(": invalid event id at line %d",
			      (int)XML_GetCurrentLineNumber(state->parser));
		} else {
			tr069_add_event(id, key);
		}
	}

	EXIT();
}

void
tr069_deserialize_events(FILE *fin)
{
	ENTER();

	char buf[BUFSIZ];
	size_t len;

	struct ctx state = {
		.version = 0
	};

	state.parser = XML_ParserCreate(NULL);

	XML_SetUserData(state.parser, &state);
	XML_SetStartElementHandler(state.parser, startEl);

	do {
		len = fread(buf, 1, sizeof(buf), fin);
		if (XML_Parse(state.parser, buf, len, len < sizeof(buf)) == XML_STATUS_ERROR) {
			debug(": %s at line %d",
			      XML_ErrorString(XML_GetErrorCode(state.parser)),
			      (int)XML_GetCurrentLineNumber(state.parser));
			break;
		}
	} while (len >= sizeof(buf));

	XML_ParserFree(state.parser);
	EXIT();
}
