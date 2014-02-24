#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
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

#define debug printf

/*
 *
 */

struct network_pool {
	int refcnt;
	uint32_t base;
	uint32_t size;
	bits_t leases[];
};

struct ip_pool {
	struct network_pool *network;
	uint32_t size;
	uint32_t min;
	uint32_t max;
	unsigned int initval;
};

static struct network_pool *new_network_pool(uint32_t base, uint32_t size)
{
	int rest;
	struct network_pool *pool;

	pool = malloc(sizeof(struct network_pool) + sizeof(bits_t) * map_size(size));
	if (!pool)
		return NULL;

	memset(pool, 0, sizeof(struct network_pool) + sizeof(bits_t) * map_size(size));
	rest = bits_size * map_size(size) - size;
	if (rest)
		/* mark bits at the end of the map as used */
		pool->leases[map_size(size) - 1] = UINT_MAX << (bits_size - rest);
	pool->base = base;
	pool->size = size;

	return pool;
}

static struct ip_pool *new_ip_pool(struct network_pool *network, uint32_t min, uint32_t max)
{
	struct ip_pool *pool;

	if (min > max)
		return NULL;

	pool = malloc(sizeof(struct ip_pool));
	if (!pool)
		return NULL;

	memset(pool, 0, sizeof(struct ip_pool));
	pool->network = network;
	network->refcnt++;
	pool->size = max - min + 1;   /* min and max are inclusive */
	pool->min = min - network->base;
	pool->max = max - network->base;
	pool->initval = havege_rand(&h_state);

	return pool;
}

static inline void free_ip_pool(struct ip_pool *pool)
{
	if (pool) {
		pool->network->refcnt--;
		if (!pool->network->refcnt)
			free(pool->network);
	}
	free(pool);
}

/* get the first bit in a pool that is not set and >= min and <= max */

/* return a bitmask with all bits > bit set */
#define MASK_LOW(bit) (UINT_MAX >> (bits_size - (bit)))

/* return a bitmask with all bits > bit set */
#define MASK_HIGH(bit) (UINT_MAX << ((bit) + 1))

/* get a mask to make all out-of-range bits as used */
static bits_t get_mask(unsigned int minpos, unsigned int minbit,
		       unsigned int maxpos, unsigned int maxbit,
		       unsigned int pos)
{
	bits_t mask = 0;

	/* mark all bits that are not part of this range as used */
	if (pos == minpos && minbit != 0) mask |= MASK_LOW(minbit);
	if (pos == maxpos && maxbit + 1 != bits_size) mask |= MASK_HIGH(maxbit);

	return mask;
}

/* get a bit that is within the range */
static unsigned int get_bit(bits_t p, bits_t mask, unsigned int bit)
{
	p |= mask;
	if (p & (1 << bit))
		bit = (ffs(~ror(p, bit)) - 1 + bit) % bits_size;

	return bit;
}

static int allocate_lease(struct ip_pool *pool, uint32_t hash)
{
	unsigned int lease;
	unsigned int pos, spos;
	unsigned int bit;
	bits_t mask;
	struct network_pool *network = pool->network;

	/* Note:
	 *  we can not trust the used accouting, as overlaping pools, network borders and static assignment are not accounted for
	 */

	unsigned int minpos = pool->min / bits_size;
	unsigned int minbit = pool->min % bits_size;
	unsigned int maxpos = pool->max / bits_size;
	unsigned int maxbit = pool->max % bits_size;

	lease = pool->min + (hash % pool->size);
	spos = pos = lease / bits_size;
	bit = lease % bits_size;

	mask = get_mask(minpos, minbit, maxpos, maxbit, pos);
	for (; pos < maxpos; pos++) {
		if ((network->leases[pos] | mask) != UINT_MAX)
			break;
		mask = 0;
	}

	/* either got an inner elememnt or the last one,
	 * mask will take care of making any bits outside the current range as used */
	mask = get_mask(minpos, minbit, maxpos, maxbit, pos);
	if ((network->leases[pos] | mask) != UINT_MAX) {
		bit = get_bit(network->leases[pos], mask, bit);
		lease = (pos * bits_size) + bit;
	} else if (pos == minpos) {
		/* did not find a lease, we are at the start of the pool
		 * this can only happen if the pool fits within one word */
		return -1;
	} else {
		mask = get_mask(minpos, minbit, maxpos, maxbit, minpos);
		for (pos = minpos; pos < spos; pos++) {
			if ((network->leases[pos] | mask) != UINT_MAX)
				break;
			mask = 0;
		}

		if (pos >= spos)
			return -1;

		/* it should be: minpos < pos < maxpos, all other case have ben handled above */
		assert(minpos <= pos);
		assert(pos < maxpos);

		bit = get_bit(network->leases[pos], mask, bit);
		lease = (pos * bits_size) + bit;
	}

	map_set_bit(network->leases, lease);
	return lease;
}

static void release_lease(struct ip_pool *pool, int lease)
{
	struct network_pool *network = pool->network;

	if (lease < INT_MAX && (unsigned int)lease >= pool->min && (unsigned int)lease <= pool->max)
		map_clear_bit(network->leases, lease);
}

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

static const char *ip2str(unsigned int ip, char *buf)
{
	struct in_addr *ipaddr = (struct in_addr *)&ip;
	return inet_ntop(AF_INET, ipaddr, buf, INET_ADDRSTRLEN);
}

void print_pool_info(struct ip_pool *pool)
{
	char ip1[INET6_ADDRSTRLEN];
	char ip2[INET6_ADDRSTRLEN];

	printf("base: %3d - %3d, size: %d, pool: %s - %s\n", (pool->min % 256) & 0xe0, (pool->max % 256) | 0x1f,
	       pool->size, ip2str(htonl(pool->min + pool->network->base), ip1), ip2str(htonl(pool->max + pool->network->base), ip2));
}

void main(void)
{
	struct network_pool *network;
	struct ip_pool *pool1;
	struct ip_pool *pool2;
	struct ip_pool *pool3;
	struct ip_pool *pool4;
	struct ip_pool *pool5;
	struct ip_pool *pool6;
	struct ip_pool *pool7;
	char bit_buf[128];
	int l = -1, l1 = -1;
	int cnt;
	bits_t bits[128] = { 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 
			     0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 
			     0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 
			     0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 0xAA, 0, 
			     0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 0x55, 0, 
	};
	int i;

	havege_init(&h_state);

	printf("bits_t size: %d\n", bits_size);

	/* 10.10.0.0/16 */
	network = new_network_pool(0x0A0A0000, 0x00010000);

	/* overlaping pools - 2 words */
	/* 10.10.1.0 - 10.10.1.31 */
	pool1 = new_ip_pool(network, 0x0A0A0100, 0x0A0A011F);
	/* 10.10.1.16 - 10.10.1.47 */
	pool2 = new_ip_pool(network, 0x0A0A0110, 0x0A0A012F);

	printf("Testing overlaping pools\n");
	print_pool_info(pool1);
	print_pool_info(pool2);
	/* testing interleaved assigment */
	cnt = 0;
	do {
		l = allocate_lease(pool1, jhash_1word(l, pool1->initval));
		if (l != -1) cnt++;
		l1 = allocate_lease(pool2, jhash_1word(l1, pool2->initval));
		if (l1 != -1) cnt++;
//		printf("new leases: %d, %d\n", l % 256, l1 % 256);
	} while (l != -1 || l1 != -1);
	printf("result: %s\n", (cnt == 48) ? "ok" : "fail");

	/* pool < bits_size */
	/* 10.10.1.64 - 10.10.1.68 */
	printf("Testing poolsize < bits_size - aligend to start of word\n");
	pool3 = new_ip_pool(network, 0x0A0A0140, 0x0A0A0144);
	print_pool_info(pool3);
	cnt = 0;
	do {
		l = allocate_lease(pool3, jhash_1word(l, pool3->initval));
		if (l != -1) cnt++;
//		printf("new leases: %d\n", l % 256);
	} while (l != -1);
	printf("result: %s\n", (cnt == 5) ? "ok" : "fail");

	/* 10.10.1.107 - 10.10.1.111 */
	printf("Testing poolsize < bits_size - in the middle of word\n");
	pool4 = new_ip_pool(network, 0x0A0A016B, 0x0A0A016F);
	print_pool_info(pool4);
	cnt = 0;
	do {
		l = allocate_lease(pool4, jhash_1word(l, pool4->initval));
		if (l != -1) cnt++;
//		printf("new leases: %d\n", l % 256);
	} while (l != -1);
	printf("result: %s\n", (cnt == 5) ? "ok" : "fail");

	/* 10.10.1.155 - 10.10.1.159 */
	printf("Testing poolsize < bits_size - aligend to end of word\n");
	pool5 = new_ip_pool(network, 0x0A0A019B, 0x0A0A019F);
	print_pool_info(pool5);
	cnt = 0;
	do {
		l = allocate_lease(pool5, jhash_1word(l, pool5->initval));
		if (l != -1) cnt++;
//		printf("new leases: %d\n", l % 256);
	} while (l != -1);
	printf("result: %s\n", (cnt == 5) ? "ok" : "fail");

	/* 10.10.1.190 - 10.10.1.194 */
	printf("Testing poolsize < bits_size - overlaping two words\n");
	pool6 = new_ip_pool(network, 0x0A0A01BE, 0x0A0A01C2);
	print_pool_info(pool6);
	cnt = 0;
	do {
		l = allocate_lease(pool6, jhash_1word(l, pool6->initval));
		if (l != -1) cnt++;
//		printf("new leases: %d\n", l % 256);
	} while (l != -1);
	printf("result: %s\n", (cnt == 5) ? "ok" : "fail");

	/* 10.10.2.5 - 10.10.2.41 */
	printf("Testing poolsize > bits_size - overlaping three words\n");
	pool7 = new_ip_pool(network, 0x0A0A0205, 0x0A0A0229);
	print_pool_info(pool7);
	cnt = 0;
	do {
		l = allocate_lease(pool7, jhash_1word(l, pool7->initval));
		if (l != -1) cnt++;
//		printf("new leases: %d\n", l % 256);
	} while (l != -1);
	printf("result: %s\n", (cnt == 37) ? "ok" : "fail");

}
