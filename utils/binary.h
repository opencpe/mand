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

#ifndef __BINARY_H
#define __BINARY_H

void dm_to64(const unsigned char *src, int len, char *dest);
int dm_from64(const unsigned char *input, unsigned char *output);
char *dm_escape_string(const uint8_t *data, int len);
int dm_unescape_string(const char *str, uint8_t *dst, int *len);

#endif
