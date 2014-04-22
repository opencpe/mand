/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "dm.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_strings.h"

#include "utils/binary.h"

#define SDEBUG
#include "debug.h"

static dm_id next_token(void *userData, const struct dm_table *kw, int type);

const char* ticks2str(char *buf, size_t sz, ticks_t n)
{
	struct tm T, *pT = &T;
	time_t secs = n / 10;
	unsigned int tks = n % 10;
	size_t l;

	if (n < 0) {
		snprintf(buf, sz, "%" PRItick, n);
	} else {
		if (!gmtime_r(&secs, pT))
			memset(pT, 0, sizeof(T));

		l = snprintf(buf, sz, "%04d-%02d-%02dT%02d:%02d:%02d",
			     (n > EPOCH) ? T.tm_year + 1900 : T.tm_year - 69, T.tm_mon + 1, T.tm_mday, T.tm_hour, T.tm_min, T.tm_sec);
		if (tks != 0 && l < sz - 1)
			l += snprintf(buf + l, sz - l, ".%d", tks);
		if ((n == 0 || n > EPOCH) && l < sz - 1)
		strcat(buf + l, "Z");
	}
	debug(": ticks: %" PRItick " -> '%s'\n", n, buf);
	return buf;
}

int str2ticks(const char *s, ticks_t *p)
{
	if (s) {
		char zone[32];
		struct tm T;
		unsigned int tks = 0;

		*zone = '\0';
		memset((void*)&T, 0, sizeof(T));

		if (sscanf(s, "%d-%d-%dT%d:%d:%d%31s", &T.tm_year, &T.tm_mon, &T.tm_mday, &T.tm_hour, &T.tm_min, &T.tm_sec, zone) < 6)
			return -1;

		T.tm_mon--;

		if (*zone == '.') {
			char *end;
			double frac;

			errno = 0;
			frac = strtod(zone, &end);
			if (errno != 0)
				return -1;
			tks = rint(frac * 10.0);
			s = end;
		} else
			s = zone;

		if (*s) {
			if (T.tm_year < 1900)
				return -1;
			T.tm_year -= 1900;

			if (*s == '+' || *s == '-') {
				int h = 0, m = 0;
				if (s[3] == ':') { /* +hh:mm */
					sscanf(s, "%d:%d", &h, &m);
					if (h < 0)
						m = -m;
				} else { /* +hhmm */
					m = (int)atol(s);
					h = m / 100;
					m = m % 100;
				}
				T.tm_min -= m;
				T.tm_hour -= h;
				/* put hour and min in range */
				T.tm_hour += T.tm_min / 60;
				T.tm_min %= 60;
				if (T.tm_min < 0) {
					T.tm_min += 60;
					T.tm_hour--;
				}
				T.tm_mday += T.tm_hour / 24;
				T.tm_hour %= 24;
				if (T.tm_hour < 0) {
					T.tm_hour += 24;
					T.tm_mday--;
				}
				/* note: day of the month may be out of range, timegm() handles it */
			}
		} else {
			/* no UTC or timezone, so assume we got relative timestamp */
			if (T.tm_year < 1 || T.tm_year > 1000)
				return -1;

			/* move year 1 to 70 for Unix Timestamp calculation */
			T.tm_year += 69;
		}
		*p = time2ticks(timegm(&T)) + tks;
	}
	return 0;
}

DM_RESULT
dm_string2value(const struct dm_element *elem, const char *str, uint8_t set_update, DM_VALUE *value)
{
	uint8_t		updated = 0;
	DM_RESULT	res = DM_OK;

	if (!elem || !str || !value)
		return DM_VALUE_NOT_FOUND;

	switch (elem->type) {
		case T_STR:
			updated = DM_STRING(*value) ? strcmp(DM_STRING(*value), str) != 0 : 1;

			res = dm_set_string_value(value, str);

			break;

		case T_BINARY:
			/* FIXME: this is not entirely correct */
			res = dm_set_binary_data(value, strlen(str), (const uint8_t *)str);
			break;

		case T_BASE64: {
			unsigned int len;
			binary_t *n;

			/* this is going to waste some bytes.... */
			len = ((strlen(str) + 4) * 3) / 4;

			n = malloc(sizeof(binary_t) + len);
			if (!n)
				return DM_OOM;

			debug(": base64 string: %zd, buffer: %d", strlen(str), len);
			n->len = dm_from64((const unsigned char *)str, n->data);
			debug(": base64 result: %d", n->len);
			updated = dm_binarycmp(DM_BINARY(*value), n) != 0;
			res = dm_set_binary_value(value, n);
			free(n);

			break;
		}

		case T_SELECTOR: {
			dm_selector sb;

			if (*str) {
				if (!dm_name2sel(str, &sb)) {
					res = DM_INVALID_VALUE;
					break;
				}
			} else
				memset(&sb, 0, sizeof(dm_selector));

			updated = DM_SELECTOR(*value) ?
					dm_selcmp(*DM_SELECTOR(*value), sb, DM_SELECTOR_LEN) != 0 : 1;

			res = dm_set_selector_value(value, sb);

			break;
		}
		case T_BOOL:
			if (!strcasecmp("true", str)) {
				updated = DM_BOOL(*value) != 1;
				set_DM_BOOL(*value, 1);
			} else if (!strcasecmp("false", str)) {
				updated = DM_BOOL(*value);
				set_DM_BOOL(*value, 0);
			} else
				res = DM_INVALID_VALUE;

			break;

		case T_ENUM: {
			int i;

			if ((i = dm_enum2int(&elem->u.e, str)) == -1)
				res = DM_INVALID_VALUE;
			else {
				updated = DM_ENUM(*value) != i;
				set_DM_ENUM(*value, i);
			}

			break;
		}
		case T_INT: {
			int32_t		i;
			char		*endl;

			i = strtol(str, &endl, 10);
			if (*endl)
				res = DM_INVALID_VALUE;
			else {
				updated = DM_INT(*value) != i;
				set_DM_INT(*value, i);
			}

			break;
		}
		case T_UINT: {
			uint32_t	i;
			char		*endl;

			i = strtoul(str, &endl, 10);
			if (*endl)
				res = DM_INVALID_VALUE;
			else {
				updated = DM_UINT(*value) != i;
				set_DM_UINT(*value, i);
			}

			break;
		}
		case T_INT64: {
			int64_t		i;
			char		*endl;

			i = strtoll(str, &endl, 10);
			if (*endl)
				res = DM_INVALID_VALUE;
			else {
				updated = DM_INT64(*value) != i;
				set_DM_INT64(*value, i);
			}

			break;
		}
		case T_UINT64: {
			uint64_t	i;
			char		*endl;

			i = strtoull(str, &endl, 10);
			if (*endl)
				res = DM_INVALID_VALUE;
			else {
				updated = DM_UINT64(*value) != i;
				set_DM_UINT64(*value, i);
			}

			break;
		}
		case T_IPADDR4: {
			struct in_addr addr;

			if (!inet_pton(AF_INET, str, &addr))
				res = DM_INVALID_VALUE;
			else {
				updated = memcmp(DM_IP4_REF(*value), &addr, sizeof(struct in_addr));
				set_DM_IP4(*value, addr);
			}

			break;
		}
		case T_IPADDR6: {
			struct in6_addr addr;

			if (!inet_pton(AF_INET6, str, &addr))
				res = DM_INVALID_VALUE;
			else {
				updated = memcmp(DM_IP6_REF(*value), &addr, sizeof(struct in6_addr));
				set_DM_IP6(*value, addr);
			}

			break;
		}
		case T_DATE: {
			time_t	val;
			char	*endl;

			val = (time_t)strtoul(str, &endl, 10);
			if (*endl)
				res = DM_INVALID_TYPE;
			else {
				updated = DM_TIME(*value) != val;
				set_DM_TIME(*value, val);
			}

			break;
		}
		case T_TICKS: {
			ticks_t	val;
			char	*endl;

			val = (ticks_t)strtoul(str, &endl, 10);
			if (*endl)
				res = DM_INVALID_TYPE;
			else {
				updated = DM_TICKS(*value) != val;
				set_DM_TICKS(*value, val);
			}

			break;
		}
		default:	/* unsupported type including T_COUNTER */
			res = DM_INVALID_TYPE;
	}

	if (res == DM_OK && set_update && updated)
		value->flags |= DV_UPDATED;

	DM_parity_update(*value);
	return res;
}

dm_selector *
dm_name2sel(const char *name, dm_selector *sel)
{
	int i;
	int st_type;
	const char *s = name;
	const struct dm_table *kw = &dm_root;

	if (!sel)
		return NULL;

	memset(sel, 0, sizeof(dm_selector));
	st_type = T_TOKEN;

	for (i = 0; i < DM_SELECTOR_LEN && kw; i++) {

		dm_id id = next_token(&s, kw, st_type);
		if (id == 0) {
			debug("(): no more elements\n");
			break;
		} else if (id == DM_ERR) {
			debug("(): error decoding reference\n");
			return NULL;
		}
		(*sel)[i] = id;

		if (st_type == T_OBJECT) {
			st_type = T_TOKEN;
			continue;
		} else {
			if (kw->table[id - 1].type == T_TOKEN || kw->table[id - 1].type == T_OBJECT) {
				if (st_type == T_TOKEN) {
					st_type = kw->table[id - 1].type;
					kw = kw->table[id - 1].u.t.table;
				} else
					debug("(): error\n");
			} else
				break;
		}
	}
	return sel;
}

static dm_id
next_token(void *userData,
	   const struct dm_table *kw,
	   int type)
{
	int i;
	char **s = userData;
	char *token;

	if (!s || !*s)
		return 0;

	token = *s;
	(*s) = strchr(token, '.');
	if (*s) {
		i = *s - token;
		(*s)++;
	} else {
		i = strlen(token);
	}
	if (type == T_OBJECT) {
		if (!isdigit(*token)) {
			return DM_ERR;
		} else
			return strtol(token, NULL, 10);
	} else
		return dm_get_element_id_by_name(token, i, kw);
}

