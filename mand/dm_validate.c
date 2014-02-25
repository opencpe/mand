/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "dm_validate.h"

#define VALCHAR	0
#define DASH	1
#define DOT 	2

int parse_tftp_url(char *url, char **host, char **path, int *port)
{
	char *pos, *end;
	int l = 1;

	if (url == NULL || strncasecmp(url, "tftp://", 7) != 0)
		goto fail;
	pos = url + 7;
	*port = 0;

	end = strchr(pos, ':');
	if (end != NULL)
		 *port = 0x010000;
	else
		end = strchr(pos, '/');
	if (end == NULL) {
		end = pos + strlen(pos);
		l = 0;
	}

	*end = '\0';
	*host = pos;
	if (!isvalhostname(*host))
		 goto fail;
	pos = end + l;

	if (*port) {
		end = strchr(pos, '/');
		if (end == NULL) {
			end = pos + strlen(pos);
			l = 0;
		}
		*end = '\0';
		*port = isport(pos);
		if (*port == 0)
			goto fail;
		pos = end + l;
	} else
		*port = 69;

	*path = pos;
	if (!**path)
		return DEFAULTFILE;
	l = isvalpath(pos);
	if (!l)
		goto fail;
	if (pos[l - 1] == '/')
		return DEFAULTFILE;
	return FULLPATH;

fail:
	*host = NULL;
	*path = NULL;
	*port = 0;
	return -1;
}

char *buildpath(const char *path, const char *filename)
{
	char *joint;
	const char *fpnt;

	if(path == NULL || filename == NULL)
		return NULL;

	fpnt = strrchr(filename, '/') + 1;
	if((joint = malloc(strlen(path) + strlen(fpnt) + 1)) == NULL)
		return NULL;

	strcpy(joint, path);
	strcat(joint, fpnt);

	return joint;
}

int isport(const char *digit)
{
	char *end;
	long int l;

	if (digit == NULL)
		return 0;

	errno = 0;
	l = strtol(digit, &end, 10);

	if (*end == '\0' && errno == 0 && l < 0xFFFF && l > 0)
		return (int)l;
	return 0;
}

int isvalip4(const char *ip)
{
	struct in_addr adr;
	if (ip == NULL)
		return 0;
	return (inet_pton(AF_INET, ip, &adr) > 0);
}

int isvalhostname(const char *host)
{
	int state = DOT;
	const char *pos = host;

	if (host == NULL)
		return 0;

	while (*pos) {
		switch (*pos) {
			case 'a' ... 'z':
			case 'A' ... 'Z':
			case '0' ... '9':
				state = VALCHAR;
				break;
			case '-':
				if (state == DOT)
					return 0;
				state = DASH;
				break;
			case '.':
				if (state == DOT || state == DASH)
					return 0;
				state = DOT;
		}
		pos++;
	}
	if (state != VALCHAR || pos - host < 4)
		return 0;
	return 1;
}

int isvalpath(const char *path)
{
	const char *pos = path;

	if (path == NULL)
		return 0;

	while (*pos) {
		switch (*pos){
			case '!' ... ',':
			case ':' ... '@':
			case '[' ... ']':
			case '`':
			case '|':
				return 0;
			default:
				pos++;
		}
	}
	return (int)(pos - path);
}
