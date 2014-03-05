/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_CACHE_H
#define __DM_CACHE_H

#include <stdint.h>
#include <sys/tree.h>

#include "dm_store.h"

struct cache_item {
        RB_ENTRY (cache_item) node;

	dm_id id;
	dm_selector sb;
	const char *name;
	const struct dm_element *elem;
	struct dm_value_table *base;

	DM_VALUE *old_value;
	DM_VALUE new_value;

	unsigned int code;
	char *msg;
};

RB_HEAD(cache, cache_item);
RB_PROTOTYPE(cache, cache_item, node, cache_compare);

extern struct cache cache;

void cache_free(void);
void cache_reset(void);
int cache_validate(void);
void cache_apply(int slot);
void cache_add(const dm_selector sb, const char *name,
	       const struct dm_element *elem,
	       struct dm_value_table *base,
	       DM_VALUE *old_value, DM_VALUE new_value,
	       unsigned int code, char *msg) __attribute__((nonnull (1)));
DM_VALUE dm_cache_get_any_value_by_id(const struct dm_value_table *, dm_id);
DM_VALUE dm_cache_get_any_value_by_selector(const dm_selector, int) __attribute__((nonnull (1)));

DM_RESULT dm_cache_get_value_by_selector_cb(const dm_selector sel, int type, void *userData,
					       DM_RESULT (*cb)(void *, const dm_selector, const struct dm_element *, const DM_VALUE))
	__attribute__((nonnull (1)));

static inline uint8_t cache_is_empty(void)
{
	return RB_ROOT(&cache) ? 0 : 1;
}

/*
 * type-safe wrapper for cache get methods
 */

/*
 * ANY
 */
static inline DM_VALUE dm_cache_get_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
DM_VALUE dm_cache_get_by_selector(const dm_selector sel)
{
	return dm_cache_get_any_value_by_selector(sel, T_ANY);
};

/*
 * BOOL
 */
static inline char dm_cache_get_bool_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
char dm_cache_get_bool_by_selector(const dm_selector sel)
{
	return DM_BOOL(dm_cache_get_any_value_by_selector(sel, T_BOOL));
};

static inline char dm_cache_get_bool_by_id(struct dm_value_table *ift, dm_id id)
{
	return DM_BOOL(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * STRING
 */
static inline const char *dm_cache_get_string_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
const char *dm_cache_get_string_by_selector(const dm_selector sel)
{
	return DM_STRING(dm_cache_get_any_value_by_selector(sel, T_STR));
};

static inline const char *dm_cache_get_string_by_id(struct dm_value_table *ift, dm_id id)
{
	return DM_STRING(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * ENUM
 */
static inline int dm_cache_get_enum_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
int dm_cache_get_enum_by_selector(const dm_selector sel)
{
	return DM_ENUM(dm_cache_get_any_value_by_selector(sel, T_ENUM));
};

static inline int dm_cache_get_enum_by_id(struct dm_value_table *ift, dm_id id)
{
	return DM_ENUM(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * INT
 */
static inline int dm_cache_get_int_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
int dm_cache_get_int_by_selector(const dm_selector sel)
{
	return DM_INT(dm_cache_get_any_value_by_selector(sel, T_INT));
};

static inline int dm_cache_get_int_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_INT(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * UINT
 */
static inline int dm_cache_get_uint_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
int dm_cache_get_uint_by_selector(const dm_selector sel)
{
	return DM_UINT(dm_cache_get_any_value_by_selector(sel, T_UINT));
};

static inline int dm_cache_get_uint_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_UINT(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * TIME
 */
static inline time_t dm_cache_get_time_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
time_t dm_cache_get_time_by_selector(const dm_selector sel)
{
	return DM_TIME(dm_cache_get_any_value_by_selector(sel, T_DATE));
};

static inline time_t dm_cache_get_time_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_TIME(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * IPv4 Address
 */
static inline struct in_addr dm_cache_get_ipv4_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
struct in_addr dm_cache_get_ipv4_by_selector(const dm_selector sel)
{
	return DM_IP4(dm_cache_get_any_value_by_selector(sel, T_IPADDR4));
};

static inline struct in_addr dm_cache_get_ipv4_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_IP4(dm_cache_get_any_value_by_id(ift, id));
};

/*
 * IPv6 Address
 */
static inline struct in6_addr dm_cache_get_ipv6_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
struct in6_addr dm_cache_get_ipv6_by_selector(const dm_selector sel)
{
	return DM_IP6(dm_cache_get_any_value_by_selector(sel, T_IPADDR6));
};

static inline struct in6_addr dm_cache_get_ipv6_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_IP6(dm_cache_get_any_value_by_id(ift, id));
};

#endif
