/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __BINARY_H
#define __BINARY_H

void dm_to64(const unsigned char *src, int len, char *dest);
int dm_from64(const unsigned char *input, unsigned char *output);
char *dm_escape_string(const uint8_t *data, int len);
int dm_unescape_string(const char *str, uint8_t *dst, int *len);

#endif
