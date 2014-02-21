/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __TR069_CACHE_H
#define __TR069_CACHE_H

#include <stdint.h>
#include <sys/tree.h>

#include "tr069_store.h"

struct cache_item {
        RB_ENTRY (cache_item) node;

	tr069_id id;
	tr069_selector sb;
	const char *name;
	const struct tr069_element *elem;
	struct tr069_value_table *base;

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
void cache_add(const tr069_selector sb, const char *name,
	       const struct tr069_element *elem,
	       struct tr069_value_table *base,
	       DM_VALUE *old_value, DM_VALUE new_value,
	       unsigned int code, char *msg) __attribute__((nonnull (1)));
DM_VALUE tr069_cache_get_any_value_by_id(const struct tr069_value_table *, tr069_id);
DM_VALUE tr069_cache_get_any_value_by_selector(const tr069_selector, int) __attribute__((nonnull (1)));

DM_RESULT tr069_cache_get_value_by_selector_cb(const tr069_selector sel, int type, void *userData,
					       DM_RESULT (*cb)(void *, const tr069_selector, const struct tr069_element *, const DM_VALUE))
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
static inline DM_VALUE tr069_cache_get_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
DM_VALUE tr069_cache_get_by_selector(const tr069_selector sel)
{
	return tr069_cache_get_any_value_by_selector(sel, T_ANY);
};

/*
 * BOOL
 */
static inline char tr069_cache_get_bool_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
char tr069_cache_get_bool_by_selector(const tr069_selector sel)
{
	return DM_BOOL(tr069_cache_get_any_value_by_selector(sel, T_BOOL));
};

static inline char tr069_cache_get_bool_by_id(struct tr069_value_table *ift, tr069_id id)
{
	return DM_BOOL(tr069_cache_get_any_value_by_id(ift, id));
};

/*
 * STRING
 */
static inline const char *tr069_cache_get_string_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
const char *tr069_cache_get_string_by_selector(const tr069_selector sel)
{
	return DM_STRING(tr069_cache_get_any_value_by_selector(sel, T_STR));
};

static inline const char *tr069_cache_get_string_by_id(struct tr069_value_table *ift, tr069_id id)
{
	return DM_STRING(tr069_cache_get_any_value_by_id(ift, id));
};

/*
 * ENUM
 */
static inline int tr069_cache_get_enum_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
int tr069_cache_get_enum_by_selector(const tr069_selector sel)
{
	return DM_ENUM(tr069_cache_get_any_value_by_selector(sel, T_ENUM));
};

static inline int tr069_cache_get_enum_by_id(struct tr069_value_table *ift, tr069_id id)
{
	return DM_ENUM(tr069_cache_get_any_value_by_id(ift, id));
};

/*
 * INT
 */
static inline int tr069_cache_get_int_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
int tr069_cache_get_int_by_selector(const tr069_selector sel)
{
	return DM_INT(tr069_cache_get_any_value_by_selector(sel, T_INT));
};

static inline int tr069_cache_get_int_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	return DM_INT(tr069_cache_get_any_value_by_id(ift, id));
};

/*
 * UINT
 */
static inline int tr069_cache_get_uint_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
int tr069_cache_get_uint_by_selector(const tr069_selector sel)
{
	return DM_UINT(tr069_cache_get_any_value_by_selector(sel, T_UINT));
};

static inline int tr069_cache_get_uint_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	return DM_UINT(tr069_cache_get_any_value_by_id(ift, id));
};

/*
 * TIME
 */
static inline time_t tr069_cache_get_time_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
time_t tr069_cache_get_time_by_selector(const tr069_selector sel)
{
	return DM_TIME(tr069_cache_get_any_value_by_selector(sel, T_DATE));
};

static inline time_t tr069_cache_get_time_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	return DM_TIME(tr069_cache_get_any_value_by_id(ift, id));
};

/*
 * IPv4 Address
 */
static inline struct in_addr tr069_cache_get_ipv4_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
struct in_addr tr069_cache_get_ipv4_by_selector(const tr069_selector sel)
{
	return DM_IP4(tr069_cache_get_any_value_by_selector(sel, T_IPADDR4));
};

static inline struct in_addr tr069_cache_get_ipv4_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	return DM_IP4(tr069_cache_get_any_value_by_id(ift, id));
};

#endif
