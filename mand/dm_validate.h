/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

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
