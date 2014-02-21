/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#include <expat.h>

#include "list.h"
#include "tr069.h"
#include "soapH.h"
#include "tr069_event_queue.h"
#include "tr069_request_queue.h"

#define SDEBUG
#include "debug.h"

struct request_node {
	struct request_node *next;
	enum req_cpe id;

	union {
		struct _TransferComplete {
			xsd__string			CommandKey;
			struct cwmp__FaultStruct	FaultStruct;
			xsd__dateTime			StartTime;
			xsd__dateTime   		CompleteTime;
		} TransferComplete;

		struct _Kicked {
			xsd__string	Command;
			xsd__string	Referer;
			xsd__string	Arg;
			xsd__string	Next;
		} Kicked;
	} u;
};

static struct {
	struct request_node	*next;
	pthread_mutex_t		mutex;
} request_head = {
	.next = NULL,
	.mutex = PTHREAD_MUTEX_INITIALIZER
};

#define MAP(X) [X] = #X
static const char *id_map[] = {
	MAP(REQ_CPE_KICKED),
	MAP(REQ_CPE_TRANS_COMPL)
};
#undef MAP

#define REQ_XML_VERSION 1

static inline int
request_id_cmp(struct request_node *node, enum req_cpe id)
{
        return INTCMP(node->id, id);
}

static struct request_node *
tr069_add_request(enum req_cpe id)
{
	struct request_node *req;

	ENTER();

	if (id <= REQ_CPE_KICKED) { /* only one entry on these types is allowed */
		struct request_node *p;

		list_search(struct request_node, request_head, id, request_id_cmp, p);
		if (p) {
			EXIT();
			return NULL;
		}
	}

	if (!(req = malloc(sizeof(struct request_node)))) {
		EXIT();
		return NULL;
	}
	memset(req, 0, sizeof(struct request_node));
	req->id = id;

	/* new or multi entry */
	list_append(struct request_node, request_head, req);

	EXIT();
	return req;
}

int
tr069_add_transfer_complete_request(
		xsd__string			CommandKey,
		struct cwmp__FaultStruct	FaultStruct,
		xsd__dateTime			StartTime,
		xsd__dateTime   		CompleteTime)
{
	struct request_node *req;

	ENTER();

	pthread_mutex_lock(&request_head.mutex);

	if ((req = tr069_add_request(REQ_CPE_TRANS_COMPL))) {
		req->u.TransferComplete.CommandKey = CommandKey && *CommandKey
					? strdup(CommandKey)
					: NULL;

		FaultStruct.FaultString = FaultStruct.FaultString && *FaultStruct.FaultString
					? strdup(FaultStruct.FaultString)
					: NULL;
		memcpy(&req->u.TransferComplete.FaultStruct, &FaultStruct,
		       sizeof(struct cwmp__FaultStruct));

		req->u.TransferComplete.StartTime = StartTime;
		req->u.TransferComplete.CompleteTime = CompleteTime;
	}

	pthread_mutex_unlock(&request_head.mutex);
	EXIT_MSG(": req %p", req);
	return !req;
}

int
tr069_add_kicked_request(
	xsd__string	Command,
	xsd__string	Referer,
	xsd__string	Arg,
	xsd__string	Next)
{
	struct request_node *req;

	ENTER();

	pthread_mutex_lock(&request_head.mutex);

	if ((req = tr069_add_request(REQ_CPE_KICKED))) {
		req->u.Kicked.Command	= Command && *Command ? strdup(Command) : NULL;
		req->u.Kicked.Referer	= Referer && *Referer ? strdup(Referer) : NULL;
		req->u.Kicked.Arg	= Arg && *Arg ? strdup(Arg) : NULL;
		req->u.Kicked.Next	= Next && *Next ? strdup(Next) : NULL;
	}

	pthread_mutex_unlock(&request_head.mutex);
	EXIT_MSG(": req %p", req);
	return !req;
}

static void
remove_request_node(struct request_node *req)
{
	list_remove(struct request_node, request_head, req);

	/* request specific cleanup */
	switch (req->id) {
	case REQ_CPE_KICKED:
		free(req->u.Kicked.Command);
		free(req->u.Kicked.Referer);
		free(req->u.Kicked.Arg);
		free(req->u.Kicked.Next);
		break;
	case REQ_CPE_TRANS_COMPL:
		free(req->u.TransferComplete.CommandKey);
		free(req->u.TransferComplete.FaultStruct.FaultString);
		break;
	}

	free(req);
}

void
tr069_clear_request_by_type(enum req_cpe id)
{
	struct request_node *req, *n;

	ENTER();
	pthread_mutex_lock(&request_head.mutex);

	list_foreach_safe(struct request_node, request_head, req, n) {
		if (!request_id_cmp(req, id))
			remove_request_node(req);
	}

	pthread_mutex_unlock(&request_head.mutex);
	EXIT();
}

extern char *kick_next_url;		/* tr.c */
extern pthread_cond_t cwmp_kick_cond;	/* tr.c */

/* FIXME??? it may be better to make the request queue public (and access it in tr.c)
	    instead of accessing global variables to apply request responses */
int
tr069_dispatch_queued_requests(struct soap *soap, const char *soap_endpoint,
			       const char *soap_action)
{
	struct request_node *req, *n;
	int r = 0;

	ENTER();
	pthread_mutex_lock(&request_head.mutex);

	list_foreach_safe(struct request_node, request_head, req, n) {
		int rc = SOAP_OK;

		switch (req->id) {
		case REQ_CPE_KICKED: {
			char *nexturl;

			rc = soap_call_cwmp__Kicked(
				soap, soap_endpoint, soap_action,
				req->u.Kicked.Command, req->u.Kicked.Referer,
				req->u.Kicked.Arg, req->u.Kicked.Next,
				&nexturl);

			remove_request_node(req);
			tr069_clear_event_by_type(EV_CPE_KICKED);

			if (rc == SOAP_OK && nexturl) {
				kick_next_url = strdup(nexturl);
			}
			pthread_cond_broadcast(&cwmp_kick_cond);
			break;
		}
		case REQ_CPE_TRANS_COMPL: {
			struct cwmp__TransferCompleteResponse response;

			rc = soap_call_cwmp__TransferComplete(
				soap, soap_endpoint, soap_action,
				req->u.TransferComplete.CommandKey,
				req->u.TransferComplete.FaultStruct,
				req->u.TransferComplete.StartTime,
				req->u.TransferComplete.CompleteTime,
				&response);

			if (rc == SOAP_OK) {
				remove_request_node(req);
				tr069_clear_event_by_type(EV_CPE_TRANS_COMPL);
				tr069_clear_event_by_type(EV_CPE_DOWNLOAD);
			}
			break;
		}
		}

		if (rc != SOAP_OK)
			soap_log_fault(soap, id_map[req->id]);
		r |= rc != SOAP_OK;
	}

	pthread_mutex_unlock(&request_head.mutex);
	EXIT();
	return r; /* false if some request failed */
}

void
tr069_serialize_xml_chardata(FILE *fout, const char *str)
{
	while (*str) {
		switch (*str) {
		default:
			if (*str >= ' ' && *str <= 'z') {
				fputc(*str, fout);
				break;
			}
			/* fall through */
		case '<':
		case '&':
		case '>':
		case '"':
		case '\'':
			fprintf(fout, "&#x%X;", *str);
			break;
		}

		str++;
	}

}

static void
serialize_faultstruct(FILE *fout, struct cwmp__FaultStruct *FaultStruct)
{
	fprintf(fout, "\t\t<FaultStruct FaultCode=\"%u\" FaultString=\"",
		FaultStruct->FaultCode);

	if (FaultStruct->FaultString)
		tr069_serialize_xml_chardata(fout, FaultStruct->FaultString);

	fprintf(fout, "\"/>\n");
}

static void
serialize_string_container(FILE *fout, const char *name, const char *str)
{
	if (str) {
		fprintf(fout, "\t\t<%s>", name);
		tr069_serialize_xml_chardata(fout, str);
		fprintf(fout, "</%s>\n", name);
	} else {
		fprintf(fout, "\t\t<%s/>\n", name);
	}
}

void
tr069_serialize_requests(FILE *fout)
{
	struct request_node *req;

	ENTER();

	fprintf(fout, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		      "\n"
		      "<requests version=\"%d\">\n",
		REQ_XML_VERSION);
	pthread_mutex_lock(&request_head.mutex);

	list_foreach(struct request_node, request_head, req) {
		switch (req->id) {
		case REQ_CPE_KICKED:		/* persistent requests */
		case REQ_CPE_TRANS_COMPL:
			break;
		default:
			continue;
		}

		fprintf(fout, "\t<request id=\"%s\">\n", id_map[req->id]);

		switch (req->id) {
		case REQ_CPE_KICKED:
			serialize_string_container(fout, "Command", req->u.Kicked.Command);
			serialize_string_container(fout, "Referer", req->u.Kicked.Referer);
			serialize_string_container(fout, "Arg", req->u.Kicked.Arg);
			serialize_string_container(fout, "Next", req->u.Kicked.Next);
			break;

		case REQ_CPE_TRANS_COMPL:
			serialize_string_container(fout, "CommandKey",
						   req->u.TransferComplete.CommandKey);
			serialize_faultstruct(fout, &req->u.TransferComplete.FaultStruct);
			fprintf(fout, "\t\t<StartTime>%" PRId64 "</StartTime>\n"
				      "\t\t<CompleteTime>%" PRId64 "</CompleteTime>\n",
				req->u.TransferComplete.StartTime,
				req->u.TransferComplete.CompleteTime);
			break;
		}

		fprintf(fout, "\t</request>\n");
	}

	pthread_mutex_unlock(&request_head.mutex);
	fprintf(fout, "</requests>\n");

	EXIT();
}

struct ctx {
	XML_Parser parser;

	int version;
	struct request_node *cur;

	char buf[1024 + 1];
};

static void XMLCALL charEl(void *, const XML_Char *, int);
static void XMLCALL rootStartEl(void *, const XML_Char *, const XML_Char **);
static void XMLCALL requestStartEl(void *, const XML_Char *, const XML_Char **);
static void XMLCALL transComplStartEl(void *, const XML_Char *, const XML_Char **);
static void XMLCALL transComplEndEl(void *, const XML_Char *);
static void XMLCALL kickedStartEl(void *, const XML_Char *, const XML_Char **);
static void XMLCALL kickedEndEl(void *, const XML_Char *);

#define FOREACH_ATT(ATTS, P) \
	for (const XML_Char **P = ATTS; *P; P += 2)

/* we expect only relatively small strings when handler is registered */
static void XMLCALL
charEl(void *userData, const XML_Char *s, int len)
{
	struct ctx *state = (struct ctx *)userData;
	size_t buflen = strlen(state->buf);

	ENTER(": buffer len %d, add %d", (int)buflen, len);

	if (buflen + len < sizeof(state->buf))
		strncat(state->buf, s, len);

	EXIT();
}

static void XMLCALL
rootStartEl(void *userData, const XML_Char *name, const XML_Char **atts)
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "requests")) {
		FOREACH_ATT(atts, pair) {
			if (!strcmp(pair[0], "version")) {
				state->version = strtol(pair[1], NULL, 0);
			}
		}

		XML_SetElementHandler(state->parser, requestStartEl, NULL);
	}

	EXIT();
}

static void XMLCALL
requestStartEl(void *userData, const XML_Char *name, const XML_Char **atts)
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "request")) {
		enum req_cpe id = REQ_CPE_MAX + 1;

		FOREACH_ATT(atts, pair) {
			if (!strcmp(pair[0], "id")) {
				for (id = 0; id <= REQ_CPE_MAX &&
					     strcmp(id_map[id], pair[1]); id++);
			}
		}

		if (id > REQ_CPE_MAX) {
			debug(": invalid request id at line %d",
			      (int)XML_GetCurrentLineNumber(state->parser));
		} else if ((state->cur = tr069_add_request(id))) {
			switch (id) {
			case REQ_CPE_KICKED:
				XML_SetElementHandler(state->parser, kickedStartEl, kickedEndEl);
				break;
			case REQ_CPE_TRANS_COMPL:
				XML_SetElementHandler(state->parser, transComplStartEl, transComplEndEl);
				break;
			}
		}
	}

	EXIT();
}

static void XMLCALL
transComplStartEl(void *userData, const XML_Char *name, const XML_Char **atts)
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "FaultStruct")) {
		struct cwmp__FaultStruct *fault = &state->cur->u.TransferComplete.FaultStruct;

		memset(fault, 0, sizeof(struct cwmp__FaultStruct));

		FOREACH_ATT(atts, pair) {
			if (!strcmp(pair[0], "FaultCode"))
				fault->FaultCode = strtoul(pair[1], NULL, 0);
			else if (!strcmp(pair[0], "FaultString"))
				fault->FaultString = *pair[1] ? strdup(pair[1]) : NULL;
		}
		debug(": FaultStruct %u %s", fault->FaultCode, fault->FaultString);

	} else if (!strcmp(name, "CommandKey") ||
		   !strcmp(name, "StartTime") ||
		   !strcmp(name, "CompleteTime")) {
		*state->buf = '\0';
		XML_SetCharacterDataHandler(state->parser, charEl);
	}

	EXIT();
}

static void XMLCALL
transComplEndEl(void *userData, const XML_Char *name)
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "CommandKey")) {
		state->cur->u.TransferComplete.CommandKey = *state->buf ? strdup(state->buf) : NULL;
		XML_SetCharacterDataHandler(state->parser, NULL);

	} else if (!strcmp(name, "StartTime")) {
		state->cur->u.TransferComplete.StartTime = strtoll(state->buf, NULL, 0);
		XML_SetCharacterDataHandler(state->parser, NULL);

	} else if (!strcmp(name, "CompleteTime")) {
		state->cur->u.TransferComplete.CompleteTime = strtoll(state->buf, NULL, 0);
		XML_SetCharacterDataHandler(state->parser, NULL);

	/* "request" level element */
	} else if (!strcmp(name, "request")) {
		XML_SetElementHandler(state->parser, requestStartEl, NULL);
	}

	EXIT();
}

static void XMLCALL
kickedStartEl(void *userData, const XML_Char *name,
	      const XML_Char **atts __attribute__((unused)))
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "Command") ||
	    !strcmp(name, "Referer") ||
	    !strcmp(name, "Arg") ||
	    !strcmp(name, "Next")) {
		*state->buf = '\0';
		XML_SetCharacterDataHandler(state->parser, charEl);
	}

	EXIT();
}

static void XMLCALL
kickedEndEl(void *userData, const XML_Char *name)
{
	struct ctx *state = (struct ctx *)userData;

	ENTER(": tag %s", name);

	if (!strcmp(name, "Command")) {
		state->cur->u.Kicked.Command = *state->buf ? strdup(state->buf) : NULL;
		XML_SetCharacterDataHandler(state->parser, NULL);

	} else if (!strcmp(name, "Referer")) {
		state->cur->u.Kicked.Referer = *state->buf ? strdup(state->buf) : NULL;
		XML_SetCharacterDataHandler(state->parser, NULL);

	} else if (!strcmp(name, "Arg")) {
		state->cur->u.Kicked.Arg = *state->buf ? strdup(state->buf) : NULL;
		XML_SetCharacterDataHandler(state->parser, NULL);

	} else if (!strcmp(name, "Next")) {
		state->cur->u.Kicked.Next = *state->buf ? strdup(state->buf) : NULL;
		XML_SetCharacterDataHandler(state->parser, NULL);

	/* "request" level element */
	} else if (!strcmp(name, "request")) {
		XML_SetElementHandler(state->parser, requestStartEl, NULL);
	}

	EXIT();
}

void
tr069_deserialize_requests(FILE *fin)
{
	ENTER();

	char buf[BUFSIZ];
	size_t len;

	struct ctx state = {
		.version = 0
	};

	state.parser = XML_ParserCreate(NULL);

	XML_SetUserData(state.parser, &state);
	XML_SetElementHandler(state.parser, rootStartEl, NULL);

	pthread_mutex_lock(&request_head.mutex);
	do {
		len = fread(buf, 1, sizeof(buf), fin);
		if (XML_Parse(state.parser, buf, len, len < sizeof(buf)) == XML_STATUS_ERROR) {
			debug(": %s at line %d",
			      XML_ErrorString(XML_GetErrorCode(state.parser)),
			      (int)XML_GetCurrentLineNumber(state.parser));
			break;
		}
	} while (len >= sizeof(buf));
	pthread_mutex_unlock(&request_head.mutex);

	XML_ParserFree(state.parser);
	EXIT();
}
