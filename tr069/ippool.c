#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <arpa/inet.h>

#if defined (HAVE_LIBPOLARSSL)
#include <polarssl/havege.h>

extern havege_state h_state;
#endif

#include "tr069_token.h"
#include "tr069_store.h"

#include "bitmap.h"
#include "ippool.h"

#define SDEBUG
#include "debug.h"

/* Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 */

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO      0x9e3779b9

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
static inline uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += initval;

        __jhash_mix(a, b, c);

        return c;
}

static inline uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
        return jhash_3words(a, b, 0, initval);
}

static inline uint32_t jhash_1word(uint32_t a, uint32_t initval)
{
        return jhash_3words(a, 0, 0, initval);
}

/*
 *
 */

struct ip_pool {
	int type;

	struct in_addr min;
	struct in_addr max;
	unsigned int min_port;
	unsigned int port_len;
	unsigned int blocks;

	unsigned int size;
	unsigned int used;
	unsigned int initval;

	bits_t leases[];
};

static struct ip_pool *new_pool(unsigned int size)
{
	int rest;
	struct ip_pool *pool;

	pool = malloc(sizeof(struct ip_pool) + sizeof(bits_t) * map_size(size));
	if (!pool)
		return NULL;

	memset(pool, 0, sizeof(struct ip_pool) + sizeof(bits_t) * map_size(size));
	rest = bits_size * map_size(size) - size;
	if (rest)
		/* mark bits at the end of the map as used */
		pool->leases[map_size(size) - 1] = UINT_MAX << (bits_size - rest);
	pool->size = size;
	pool->initval = havege_rand(&h_state);

	return pool;
}

static inline void free_pool(struct ip_pool *pool)
{
	free(pool);
}

static int allocate_lease(struct ip_pool *pool, uint32_t hash)
{
	unsigned int lease;
	unsigned int pos, spos;
	unsigned int bit;

	if (pool->used == pool->size)
		return -1;

	lease = hash % pool->size;
	spos = pos = lease / bits_size;
	bit = lease % bits_size;

	for (; pos < map_size(pool->size); pos++)
		if (pool->leases[pos] != UINT_MAX)
			break;

	if (pos >= map_size(pool->size))
		/* didn't find a free spot, try again from the start */
		for (pos = 0; pos < spos; pos++)
			if (pool->leases[pos] != UINT_MAX)
				break;

	/* should be redundant, but better be safe */
	if (pool->leases[pos] == UINT_MAX)
		return -1;

	if ((pool->leases[pos] & (1 << bit)))
		bit = (ffs(~ror(pool->leases[pos], bit)) - 1 + bit) % bits_size;

	/* should be redundant, but better be safe */
	if ((pos * bits_size) + bit >= pool->size)
		return -1;

	pool->leases[pos] |= (1 << bit);
	pool->used++;

	return (pos * bits_size) + bit;
}

static void release_lease(struct ip_pool *pool, unsigned int lease)
{
	if (lease < pool->size) {
		map_clear_bit(pool->leases, lease);
		pool->used--;
	}
}

static int get_lease(struct ip_pool *pool, unsigned int lease)
{
	if (lease < pool->size)
		return map_get_bit(pool->leases, lease);
	else
		return 1;
}

#ifndef STANDALONE
struct ip_pool *get_pool(struct tr069_value_table *nat)
{
	int type;
	struct ip_pool *pool;

	ENTER();

	type = tr069_get_enum_by_id(nat, cwmp__IGD_SCG_NP_i_Translation);
	switch (type) {
	case cwmp___IGD_SCG_NP_i_Translation_SymetricAddressKeyed:
	case cwmp___IGD_SCG_NP_i_Translation_AddressKeyed:
	case cwmp___IGD_SCG_NP_i_Translation_PortKeyed:
		break;

	default:
		EXIT();
		return 0;
	}

	pool = tr069_get_ptr_by_id(nat, cwmp__IGD_SCG_NP_i_X_DM_PoolInfo);
	if (!pool) {
		unsigned int size;

		struct in_addr min;
		struct in_addr max;

		unsigned int min_port = 0;
		unsigned int max_port = 0;
		unsigned int port_len = 0;
		unsigned int blocks = 0;

		min = tr069_get_ipv4_by_id(nat, cwmp__IGD_SCG_NP_i_MinAddress);
		max = tr069_get_ipv4_by_id(nat, cwmp__IGD_SCG_NP_i_MaxAddress);

		size = ntohl(max.s_addr) - ntohl(min.s_addr) + 1;
		if (type == cwmp___IGD_SCG_NP_i_Translation_PortKeyed) {
			min_port = tr069_get_uint_by_id(nat, cwmp__IGD_SCG_NP_i_MinPort);
			max_port = tr069_get_uint_by_id(nat, cwmp__IGD_SCG_NP_i_MaxPort);
			port_len = tr069_get_uint_by_id(nat, cwmp__IGD_SCG_NP_i_PortKeyLen);

			if (!min_port)
				min_port = 1024;
			else if (min_port < 1024) {
				EXIT_MSG("min_port < 1024");
				return 0;
			}
			if (!max_port)
				max_port = 65535;
			if (max_port < min_port) {
				EXIT_MSG("max_port < min_port");
				return 0;
			}
			blocks = (max_port - min_port + 1) / port_len;
			if (blocks == 0) {
				EXIT_MSG("blocks == 0");
				return 0;
			}

			size *= blocks;
		}

		pool = new_pool(size);
		tr069_set_ptr_by_id(nat, cwmp__IGD_SCG_NP_i_X_DM_PoolInfo, pool);
		if (!pool) {
			EXIT_MSG("no pool");
			return 0;
		}

		pool->type = type;
		pool->min = min;
		pool->max = max;
		pool->min_port = min_port;
		pool->port_len = port_len;
		pool->blocks = blocks;
	}
	else if (pool->type != type) {
		EXIT_MSG("pool type mismatch");
		return 0;
	}

	EXIT_MSG("pool: %p", pool);
	return pool;
}

int alloc_natpool_addr(struct tr069_value_table *nat, struct in_addr orig, struct in_addr *addr, unsigned int *start_port, unsigned int *end_port)
{
	struct ip_pool *pool;
	int lease;
	uint32_t hash;

	ENTER();

	*addr = (struct in_addr){ .s_addr = INADDR_NONE};
	*start_port = 0;
	*end_port = 0;

	if (!tr069_get_bool_by_id(nat, cwmp__IGD_SCG_NP_i_Enabled)) {
		EXIT();
		return 0;
	}

	pool = get_pool(nat);
	if (!pool) {
		EXIT();
		return 0;
	}

	hash = jhash_1word(orig.s_addr, pool->initval);
	lease = allocate_lease(pool, hash);
	if (lease < 0) {
		EXIT_MSG("no lease");
		return 0;
	}

	if (pool->type == cwmp___IGD_SCG_NP_i_Translation_PortKeyed) {
		addr->s_addr = htonl(ntohl(pool->min.s_addr) + lease / pool->blocks);
		*start_port = pool->min_port + (lease % pool->blocks) * pool->port_len;
		*end_port = *start_port + pool->port_len - 1;
	} else
		addr->s_addr = htonl(ntohl(pool->min.s_addr) + lease);

	EXIT_MSG("lease #%d", lease);
	return 1;
}

void release_natpool_addr(struct tr069_value_table *nat, struct in_addr addr, unsigned int start_port)
{
	struct ip_pool *pool;
	int lease;

	if (!tr069_get_bool_by_id(nat, cwmp__IGD_SCG_NP_i_Enabled))
		return;

	pool = get_pool(nat);
	if (!pool) {
		EXIT();
		return;
	}

	if (ntohl(addr.s_addr) < ntohl(pool->min.s_addr) ||
	    ntohl(addr.s_addr) > ntohl(pool->max.s_addr))
		return;

	lease = ntohl(addr.s_addr) - ntohl(pool->min.s_addr);
	if (pool->type == cwmp___IGD_SCG_NP_i_Translation_PortKeyed) {
		unsigned int block;

		if (start_port < pool->min_port)
			return;
		/* start_pool does not fall onto a port_len bondary */
		if ((start_port - pool->min_port) % pool->port_len)
			return;
		block = (start_port - pool->min_port) / pool->port_len;
		if (block >= pool->blocks)
			return;
		lease *= pool->blocks;
		lease += block;
	}
	release_lease(pool, lease);
}

/* check if NAT pool IP is valid and available
 *
 * return 0 (false) if the address invalid or taken,
 * return 1 (true) if the address is valid and available
 */
int check_natpool_addr(struct tr069_value_table *nat, struct in_addr addr, unsigned int start_port)
{
	struct ip_pool *pool;
	int lease;

	ENTER();

	if (!tr069_get_bool_by_id(nat, cwmp__IGD_SCG_NP_i_Enabled)) {
		EXIT();
		return 0;
	}

	pool = get_pool(nat);
	if (!pool) {
		EXIT();
		return 0;
	}

	if (ntohl(addr.s_addr) < ntohl(pool->min.s_addr) ||
	    ntohl(addr.s_addr) > ntohl(pool->max.s_addr)) {
		EXIT();
		return 0;
	}

	lease = ntohl(addr.s_addr) - ntohl(pool->min.s_addr);
	if (pool->type == cwmp___IGD_SCG_NP_i_Translation_PortKeyed) {
		unsigned int block;

		if (start_port < pool->min_port)
			return 0;
		/* start_pool does not fall onto a port_len bondary */
		if ((start_port - pool->min_port) % pool->port_len)
			return 0;
		block = (start_port - pool->min_port) / pool->port_len;
		if (block >= pool->blocks)
			return 0;
		lease *= pool->blocks;
		lease += block;
	}
	EXIT_MSG("lease: %d", get_lease(pool, lease));
	return !(get_lease(pool, lease));
}
#endif

#ifdef STANDALONE
char *putbits(char *buf, int val)
{
	int i;
	char *p = buf;

	for (i = bits_size - 1; i; i--)
		*p++ = (val & (1 << i)) ? '1' : '0';
	*p = '\0';
	return buf;
}

havege_state h_state;

void main(void)
{
	struct ip_pool *pool;
	char bit_buf[128];
	int l;
	bits_t bits[128] = { 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0,
			     0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0,
			     0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0,
			     0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0,
			     0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0,
	};
	int i;

	havege_init(&h_state);

/*
	for (i = 0; i < bits_size; i++)
		printf("ror %2d: %s\n", i, putbits(bit_buf, ror(0x12345678, i)));

	for (i = 0; i < 12 * bits_size; i++)
		printf("bit %4d: %d\n", i, get_bit(bits, i));

	printf ("byte: %08x\n", bits[0]);
	printf("bit 10: %d\n", get_bit(bits, 10));
	set_bit(bits, 10);
	printf ("byte: %08x\n", bits[0]);
	printf("bit 10: %d\n", get_bit(bits, 10));
	clear_bit(bits, 10);
	printf ("byte: %08x\n", bits[0]);
	printf("bit 10: %d\n", get_bit(bits, 10));
*/


	pool = new_pool(15);
	for (i = 0; i < 19; i++) {
		l = allocate_lease(pool, jhash_1word(i, pool->initval));
		printf("new lease: %d\n", l);
	}
}

#endif
