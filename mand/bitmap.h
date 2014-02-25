/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __BITMAP_H
#define __BITMAP_H

typedef unsigned int bits_t;
#define bits_size (sizeof(bits_t) * 8)
#define map_size(x) ((x + bits_size - 1) / bits_size)

static inline int map_get_bit(bits_t *map, int id)
{
	return (map[id / bits_size] >> (id % bits_size)) & 1;
}

static inline void map_set_bit(bits_t *map, int id)
{
	map[id / bits_size] |= 1 << (id % bits_size);
}

static inline void map_clear_bit(bits_t *map, int id)
{
	map[id / bits_size] &= ~(1 << (id % bits_size));
}

static inline int map_ffz(bits_t *map, size_t size)
{
	size_t i;
	int n;

	for (i = 0; i < size; i++)
		if ((n = ffs(~map[i])) != 0)
			return i * bits_size + n - 1;

	return -1;
}

static inline int map_ffs(bits_t *map, size_t size)
{
	size_t i;
	int n;

	for (i = 0; i < size; i++)
		if ((n = ffs(map[i])) != 0)
			return i * bits_size + n - 1;

	return -1;
}

static inline bits_t ror(bits_t b, int pos)
{
	return b >> pos | b << (bits_size - pos);
}

#endif
