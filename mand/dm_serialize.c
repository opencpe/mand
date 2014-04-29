/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include "dm.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_serialize.h"
#include "dm_strings.h"
#include "dm_cfgversion.h"

#include "utils/binary.h"

//#define SDEBUG
#include "debug.h"

#define XML_INDENT "    "

static void findent(FILE *stream, int level)
{
	for (; level > 0; level--)
		fprintf(stream, XML_INDENT);
}

struct walk_data {
	FILE *stream;
	int flags;
	int indent;
};

#if defined (SDEBUG)
#define initCB2S(x) [x] = #x

static char *cb2str[] = {
	initCB2S(CB_element),
	initCB2S(CB_table_start),
	initCB2S(CB_table_end),
	initCB2S(CB_object_start),
	initCB2S(CB_object_end),
	initCB2S(CB_object_instance_start),
	initCB2S(CB_object_instance_end),
};
#endif

/*
#x20 | #xD | #xA | [a-zA-Z0-9] | [-'()+,./:=?;!*#@$_%]
*/


static int validate_cdata(const char *str, int len)
{
	int r = 0;
	int cend = 0;

	while (len) {
		if (*str > 'z' || *str < ' ')
			r |= 2;

		switch (*str) {
		case '<':
		case '&':
			r|= 1;
			cend = 0;
			break;
		case ']':
			cend++;
			break;
		case '>':
			r|= 1;
			cend++;
			if (cend > 2)
				return -1;
			break;
		default:
			cend = 0;
		}
		str++;
		len--;
	}
	return r;
}

static void string_escape(FILE *stream, const char *key, const char *nfbuf, const char *value, int len)
{
	fprintf(stream, "<%s%s encoding=\"escaped\">", key, nfbuf);
	while (len) {
		if (*value > 'z' || *value < ' ' ||
		    *value == '<' || *value == '&' || *value == '>') {
			fprintf(stream, "\\%03o", *value);
		} else
			fprintf(stream, "%c", *value);
		value++;
		len--;
	}
	fprintf(stream, "</%s>\n", key);
}

static void serialize_binary(FILE *stream, const char *key, const char *nfbuf, const uint8_t *value, int len)
{
	fprintf(stream, "<%s%s>", key, nfbuf);
	while (len) {
		if (*value == '<') {
			fprintf(stream, "&lt;");
		} else if (*value == '&') {
			fprintf(stream, "&amp;");
		} else if (*value == '>') {
			fprintf(stream, "&gt;");
		} else if (*value > 'z' || *value < ' ') {
			fprintf(stream, "&#x%02X;", *value);
		} else
			fprintf(stream, "%c", *value);
		value++;
		len--;
	}
	fprintf(stream, "</%s>\n", key);
}

static void serialize_element(FILE *stream,
			      int flags __attribute__ ((unused)),
			      int indent,
			      const struct dm_element *elem, const DM_VALUE value)
{
	char nfbuf[64] = "";

	/*
	if (!(elem->flags & F_WRITE))
		return;
	*/

	if (value.notify & 0x0003)
		snprintf(nfbuf, sizeof(nfbuf), " notify=\"%s\"", dm_int2enum(&notify_attr, value.notify & 0x0003));

	switch(elem->type) {
		case T_BOOL:
			findent(stream, indent);
			fprintf(stream, "<%s%s>%s</%s>\n", elem->key, nfbuf, DM_BOOL(value) ? "true" : "false", elem->key);
			break;
		case T_COUNTER:
			/* don't serialize counters */
			if (value.notify & 0x0003) {
				findent(stream, indent);
				fprintf(stream, "<%s%s />\n", elem->key, nfbuf);
			}
			break;

		case T_BINARY:
			findent(stream, indent);
			if (DM_BINARY(value) && DM_BINARY(value)->len != 0)
				serialize_binary(stream, elem->key, nfbuf, DM_BINARY(value)->data, DM_BINARY(value)->len);
			else
				fprintf(stream, "<%s%s />\n", elem->key, nfbuf);
			break;

		case T_BASE64:
			if (DM_BINARY(value) && DM_BINARY(value)->len != 0) {
				char *buf;
				int r;

				r = ((DM_BINARY(value)->len + 3) * 4) / 3;
				buf = malloc(r);
				if (buf) {
					debug(": base64 len: %d, buffer: %d", DM_BINARY(value)->len, r);
					dm_to64(DM_BINARY(value)->data, DM_BINARY(value)->len, buf);
					debug(": base64 result len: %d", strlen(buf));

					findent(stream, indent);
					fprintf(stream, "<%s%s >\n", elem->key, nfbuf);
					for (int i = 0; i < r; i += 64) {
						findent(stream, indent + 1);
						if (fprintf(stream, "%.64s\n", &buf[i]) < 0)
							break;
					}
					findent(stream, indent);
					fprintf(stream, "</%s>\n", elem->key);

					free(buf);
					break;
				}
			}

			findent(stream, indent);
			fprintf(stream, "<%s%s />\n", elem->key, nfbuf);
			break;

		case T_DATE: {
			char buf[40];

			ticks2str(buf, sizeof(buf), time2ticks(DM_TIME(value)));
/*
			struct tm tm;
			gmtime_r(DM_TIME_REF(value), &tm);
			strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
*/
			findent(stream, indent); fprintf(stream, "<%s%s>%s</%s>\n", elem->key, nfbuf, buf, elem->key);
			break;
		}
		case T_TICKS: {
			if (elem->flags & F_DATETIME) {
				char buf[40];

				ticks2str(buf, sizeof(buf), ticks2realtime(DM_TICKS(value)));
				findent(stream, indent); fprintf(stream, "<%s%s>%s</%s>\n", elem->key, nfbuf, buf, elem->key);
			} else {
				findent(stream, indent); fprintf(stream, "<%s%s>%" PRItick "</%s>\n", elem->key, nfbuf, DM_TICKS(value), elem->key);
			}
			break;
		}
		case T_UINT:
			findent(stream, indent); fprintf(stream, "<%s%s>%u</%s>\n", elem->key, nfbuf, DM_UINT(value), elem->key);
			break;
		case T_INT:
			findent(stream, indent); fprintf(stream, "<%s%s>%d</%s>\n", elem->key, nfbuf, DM_INT(value), elem->key);
			break;
		case T_UINT64:
			findent(stream, indent); fprintf(stream, "<%s%s>%"PRIu64"</%s>\n", elem->key, nfbuf, DM_UINT64(value), elem->key);
			break;
		case T_INT64:
			findent(stream, indent); fprintf(stream, "<%s%s>%"PRId64"</%s>\n", elem->key, nfbuf, DM_INT64(value), elem->key);
			break;
		case T_ENUM:
			findent(stream, indent); fprintf(stream, "<%s%s>%s</%s>\n",
							 elem->key, nfbuf, dm_int2enum(&elem->u.e, DM_ENUM(value)), elem->key);
			break;
		case T_STR:
			findent(stream, indent);
			if (DM_STRING(value) && strlen(DM_STRING(value)) != 0) {
				int r;

				r = validate_cdata(DM_STRING(value), strlen(DM_STRING(value)));
				if (r == 0)
					fprintf(stream, "<%s%s>%s</%s>\n", elem->key, nfbuf, DM_STRING(value), elem->key);
				else if ((r & 2) == 2)
					string_escape(stream, elem->key, nfbuf, DM_STRING(value), strlen(DM_STRING(value)));
				else if ((r & 1) == 1)
					fprintf(stream, "<%s%s><![CDATA[%s]]></%s>\n", elem->key, nfbuf, DM_STRING(value), elem->key);
				else if (r < 0)
					fprintf(stream, "<%s%s>%s</%s>\n", elem->key, nfbuf, "invalid CDATA content", elem->key);

			} else
				fprintf(stream, "<%s%s />\n", elem->key, nfbuf);
			break;
		case T_SELECTOR: {
			char buf[MAX_PARAM_NAME_LEN];
			char *s = NULL;

			findent(stream, indent);
			if (DM_SELECTOR(value))
				s = dm_sel2name(*DM_SELECTOR(value), buf, sizeof(buf));
			if (s) {
				fprintf(stream, "<%s%s>%s</%s>\n", elem->key, nfbuf, s, elem->key);
			} else
				fprintf(stream, "<%s%s />\n", elem->key, nfbuf);
			break;
		}
	        case T_IPADDR4: {
			char s[INET_ADDRSTRLEN];

			inet_ntop(AF_INET, DM_IP4_REF(value), s, sizeof(s));
			findent(stream, indent); fprintf(stream, "<%s%s>%.*s</%s>\n", elem->key, nfbuf, INET_ADDRSTRLEN, s, elem->key);
			break;
		}
	        case T_IPADDR6: {
			char s[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, DM_IP6_REF(value), s, sizeof(s));
			findent(stream, indent); fprintf(stream, "<%s%s>%.*s</%s>\n", elem->key, nfbuf, INET6_ADDRSTRLEN, s, elem->key);
			break;
		}
		case T_TOKEN:
		case T_OBJECT:
		default:
			fprintf(stderr, "unexpected element type: %s: %d (%p)\n", elem->key, elem->type, elem);
			break;

	}
}

static int serialize_walk_cb(void *userData, CB_type type, dm_id id,
			     const struct dm_element *elem, const DM_VALUE value)
{
	int r = 1;
	struct walk_data *w = (struct walk_data *)userData;

	debug(": %s, key: %s, flags: %x, F_INTERNAL: %d, value flags: %04x, upd: %d, ntfy: %d",
	      cb2str[type],
	      elem->key, elem->flags, elem->flags & F_INTERNAL,
	      value.flags, !!(value.flags & DV_UPDATED), !!(value.flags & DV_NOTIFY));

	if ((elem->flags & F_INTERNAL) != 0)
		return r;

	if ((value.flags & (DV_UPDATED | DV_NOTIFY)) == 0 && (w->flags & S_SYS) == 0)
		return 0;

	switch (type) {
		case CB_object_instance_start:
			debug(": %d", id);
			if (((id & DM_ID_AUTO_OBJECT) != DM_ID_AUTO_OBJECT &&
			     (elem->flags & F_SYSTEM) == 0) ||
			    (w->flags & S_SYS) != 0) {
				findent(w->stream, w->indent);
				fprintf(w->stream, "<%s instance='%hu'>\n", elem->key, id);
				w->indent++;
			} else
				r = 0;
			break;
		case CB_table_start:
			if ((elem->flags & F_SYSTEM) == 0 ||
			    (w->flags & S_SYS) != 0) {
				findent(w->stream, w->indent);
				if (elem->flags & F_VERSION)
					fprintf(w->stream, "<%s version=\"%d\">\n", elem->key, CFG_VERSION);
				else
					fprintf(w->stream, "<%s>\n", elem->key);
				w->indent++;
			} else
				r = 0;
			break;
		case CB_table_end:
		case CB_object_instance_end:
			w->indent--;
			findent(w->stream, w->indent);
			fprintf(w->stream, "</%s>\n", elem->key);
			break;
		case CB_element:
			if (((elem->flags & F_WRITE) != 0 &&
			     (elem->flags & F_SYSTEM) == 0) ||
			    (w->flags & S_SYS) != 0)
				serialize_element(w->stream, w->flags, w->indent, elem, value);
			break;
		default:
			break;
	}
	return r;
}

void dm_serialize_store(FILE *stream, int flags)
{
	struct walk_data w;

	w.stream = stream;
	w.flags = flags;
	w.indent = 1;

	dm_update_flags();

	fprintf(stream, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf(stream, "<OpenCPE version=\"%d\">\n", CFG_VERSION);
	dm_walk_table_cb(DM_SELECTOR_LEN, &w, serialize_walk_cb, &dm_root, dm_value_store);
	fprintf(stream, "</OpenCPE>\n");
}

void dm_serialize_element(FILE *stream, const char *element, int flags)
{
	struct walk_data w;
	dm_selector sel;

	if (!dm_name2sel(element, &sel))
		return;

	dm_update_flags();

	w.stream = stream;
	w.flags = flags;
	w.indent = 1;

	fprintf(stream, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
	fprintf(stream, "<data>\n");
	dm_walk_by_selector_cb(sel, DM_SELECTOR_LEN, &w, serialize_walk_cb);
	fprintf(stream, "</data>\n");
}

