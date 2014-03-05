/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "binary.h"

static char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void
output64chunk(const uint8_t c[3], int pads, char *dest)
{
    char *d = dest;

    *d = basis_64[c[0] >> 2]; d++;
    *d = basis_64[((c[0] & 0x3) << 4) | ((c[1] & 0xF0) >> 4)]; d++;
    if (pads == 2) {
        *d = '='; d++;
        *d = '='; d++;
    } else if (pads) {
        *d = basis_64[((c[1] & 0xF) << 2) | ((c[2] & 0xC0) >> 6)]; d++;
        *d = '='; d++;
    } else {
        *d = basis_64[((c[1] & 0xF) << 2) | ((c[2] & 0xC0) >> 6)]; d++;
        *d = basis_64[c[2] & 0x3F]; d++;
    }

}

void dm_to64(const unsigned char *src, int len, char *dest)
{
	uint8_t c[3];
	int j, ct = 0, i = 0;
	const unsigned char * s = src;
	char *d = dest;
	
	while (i < len) {
		c[0] = c[1] = c[2] = 0;
		for (j = 0; j < 3 && i + j < len; j++)
			     c[j] = *s++;

		output64chunk(c, 3 - j, d);
		ct += 4; d += 4; i += 3;
	}
	*d = '\0';
}

static uint8_t getbits(uint8_t input)
{
        if ((input >='A') && (input <='Z')) {
                return ((uint8_t)input - (uint8_t) 'A');
        } else if ((input >='a') && (input <='z')) {
                return ((uint8_t)input - (uint8_t) 'a' + 26);
        } else if ((input >='0') && (input <='9')) {
                return ((uint8_t)input - (uint8_t) '0' + 52);
        } else if (input =='+') {
                return 62;
        } else if (input =='/') {
                return 63;
        } else {
                return 0;
        }
}

int dm_from64(const unsigned char *input, unsigned char *output)
{
        int len = 0;
        int i = 0;
        int bits = 0;

        for (; *input; input++) {
		/* skip white space on decoder bondary */
		if ((i % 8) == 0 &&
		    (*input == '\n' ||
		     *input == '\r' ||
		     *input == '\t' ||
		     *input == ' '))
			continue;

		if (*input == '=')
			break;

                bits |= getbits(*input);
                i += 6;
                if (i > 8) {
                        i %= 8;
                        *output++ = (uint8_t)(bits >> i);
                        len++;
                }
                bits <<= 6;
        }

        if (i != 0 && *input != '=') {
                *output++ = (uint8_t)(bits >> (i - 2));
                len++;
        }

        *output = '\0';

        return len;
}

#define BLOCK_ALLOC 128

char *dm_escape_string(const uint8_t *data, int len)
{
        char *buf;
        int space, p;

        space = (((len + 8) / BLOCK_ALLOC) + 1) * BLOCK_ALLOC;
        buf = malloc(space);
        if (!buf)
                return NULL;
        p = 0;

        while (len) {
                /* make sure we have enough space left */
                if (space - p < 5) {
                        buf = realloc(buf, space + BLOCK_ALLOC);
                        if (!buf)
                                return NULL;
                        space += BLOCK_ALLOC;
                }
                switch (*data) {
                case   0 ... 31:
                case 127 ... 255:
                        p += sprintf(buf + p, "\\%03o", *data);
                        break;

                case '\\':
                        buf[p++] = '\\';
                        /* fall through */

                default:
                        buf[p++] = *data;
                        break;
                }
                data++;
                len--;
        }
        buf[p] = '\0';

	return buf;
}

int dm_unescape_string(const char *str, uint8_t *dst, int *len)
{
        int pos = 0;

        while (*str && pos < *len) {
                if (*str != '\\') {
                        dst[pos++] = *str++;
                        continue;
                }

                str++;
                if (*str == '\\') {
                        dst[pos++] = *str++;
                        continue;
                }

                dst[pos] = 0;
                for (int i = 2; i >= 0; i--, str++) {
                        if (*str < '0' || *str > '9') {
                                *len = 0;
                                return -1;
                        }
                        dst[pos] += (*str - '0') << i * 3;
                }
                pos++;
        }

        dst[pos] = 0;
        *len = pos;

        return 0;
}
