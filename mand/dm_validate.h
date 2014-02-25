/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_VALIDATE_H
#define __DM_VALIDATE_H

int parse_tftp_url(char *url, char **host, char **path, int *port);
char *buildpath(const char *path, const char *filename);

#define DEFAULTFILE	1
#define FULLPATH	2

int isport(const char *digit);
int isvalip4(const char *ip);
int isvalhostname(const char *host);
int isvalpath(const char *path);

#endif
