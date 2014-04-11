/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_STORE_H
#define __DM_STORE_H

#include "dm.h"
#include "dm_token.h"
#include "p_table.h"
#include "dm_notify.h"
#include "dmd.h"

#define DM_MEM_ACCOUNTING

#if defined(DM_MEM_ACCOUNTING)
extern int dm_mem;

#define DM_MEM_ADD(x) dm_mem += x
#define DM_MEM_SUB(x) dm_mem -= x
#else
#define DM_MEM_ADD(x) do {} while (0)
#define DM_MEM_SUB(x) do {} while (0)
#endif

#define DM_ID_USER_OBJECT   0x8000
#define DM_ID_AUTO_OBJECT   0xC000
#define DM_ID_MASK          0x3FFF

typedef enum {
	CB_element,
	CB_table_start,
	CB_table_end,
	CB_object_start,
	CB_object_end,
	CB_object_instance_start,
	CB_object_instance_end,
} CB_type;

		/* prototype for functions like dm_get_value_by_selector_cb */
typedef DM_RESULT (*GET_BY_SELECTOR_CB)(const dm_selector sel, int type,
					void *userData,
					DM_RESULT (*cb)(void *,
							const dm_selector,
							const struct dm_element *,
							const DM_VALUE));

dm_id dm_get_element_id_by_name(const char *name, size_t l, const struct dm_table *kw);

#define MAX_PARAM_NAME_LEN 257

char *dm_sel2name(const dm_selector, char *, int size) __attribute__((nonnull (1)));

int dm_get_element_by_selector(const dm_selector, struct dm_element **);

char *dm_normalize_list(char *str);
char *dm_add2list(char *list, char *str);
char *dm_listdel(char *l, char *str);
int dm_listcontains(char *l, char *str);

/* generic set functions */
DM_RESULT dm_set_any_value_by_selector(const dm_selector sel, int type, const DM_VALUE val) __attribute__((nonnull (1)));
DM_RESULT dm_overwrite_any_value_by_selector(const dm_selector sel, int type, DM_VALUE val, int slot) __attribute__((nonnull (1)));

/* generic get functions */
DM_VALUE dm_get_any_value_by_selector(const dm_selector sel, int type) __attribute__((nonnull (1)));

DM_RESULT dm_set_string_value(DM_VALUE *st, const char *s);
DM_RESULT dm_set_binary_value(DM_VALUE *st, const binary_t *b);
DM_RESULT dm_set_binary_data(DM_VALUE *st, unsigned int len, const uint8_t *data);
DM_RESULT dm_set_selector_value(DM_VALUE *st, const dm_selector s);

int dm_get_value_by_selector(const dm_selector sel, int type, void *value) __attribute__((nonnull (1)));

DM_RESULT dm_get_value_by_selector_cb(const dm_selector sel, int type, void *userData,
					 DM_RESULT (*cb)(void *, const dm_selector, const struct dm_element *, const DM_VALUE))
	 __attribute__((nonnull (1)));

DM_RESULT dm_set_value_by_selector(const dm_selector sel, int type, const void *value) __attribute__((nonnull (1)));

DM_RESULT dm_set_value_by_selector_cb(const dm_selector sel, void *value,
				   void *userData, DM_RESULT (*cb)(void *, const dm_selector, const struct dm_element *,
								   const void *, DM_VALUE *))
	__attribute__((nonnull (1)));

DM_RESULT dm_get_value_ref_by_selector_cb(const dm_selector sel, void *value,
					     void *userData, DM_RESULT (*cb)(void *,
									     const dm_selector,
									     const struct dm_element *,
									     struct dm_value_table *,
									     const void *,
									     DM_VALUE *))
	__attribute__((nonnull (1)));

struct dm_value_table *dm_alloc_table(const struct dm_table *, const dm_selector, dm_id);
void dm_init_table(const struct dm_table *, struct dm_value_table *, const dm_selector, dm_id);
struct dm_value_table *dm_extend_table(struct dm_value_table *told, int size);

struct dm_instance_node *dm_add_instance_by_selector(const dm_selector sel, dm_id *id) __attribute__((nonnull (1)));

int dm_add_table_by_selector(const dm_selector sel) __attribute__((nonnull (1)));

int dm_del_table_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
int dm_del_object_by_selector(const dm_selector sel) __attribute__((nonnull (1)));

void dm_update_flags(void);

DM_VALUE *dm_get_instance_node_ref_by_id(struct dm_instance *, dm_id);

struct dm_instance_node *dm_get_instance_node_by_selector(const dm_selector) __attribute__((nonnull (1)));
struct dm_instance_node *dm_get_instance_node_by_id(struct dm_instance *, dm_id);

int dm_mark_updated_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
const struct dm_table *dm_get_object_table_by_selector(const dm_selector sel) __attribute__((nonnull (1)));

/*
 * DM_VALUE memory helper
 */
static inline void dm_free_string_value(DM_VALUE *);
static inline void dm_free_binary_value(DM_VALUE *);
static inline void dm_free_selector_value(DM_VALUE *);
static inline void dm_free_any_value(const struct dm_element *, DM_VALUE *);

/*
 * notify helper
 */
static inline void dm_notify_by_id(struct dm_value_table *, dm_id);

/*
 * access to value flags
 */
static inline uint16_t dm_get_flags_by_id(struct dm_value_table *, dm_id);

/*
 * type-safe get/set methods
 */

/* DM_VALUE */
static inline DM_VALUE  dm_get_by_selector(const dm_selector) __attribute__((nonnull (1)));

static inline DM_VALUE *dm_get_value_ref_by_id(struct dm_value_table *, dm_id);
static inline DM_VALUE *dm_get_value_ref_by_index(struct dm_value_table *, dm_id);

/* pointer */
static inline void *dm_get_ptr_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int   dm_set_ptr_by_selector(const dm_selector, void *, int) __attribute__((nonnull (1)));

static inline void *dm_get_ptr_by_id(struct dm_value_table *, dm_id);
static inline void  dm_set_ptr_by_id(struct dm_value_table *, dm_id, void *);

/* bool */
static inline char dm_get_bool_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int  dm_set_bool_by_selector(const dm_selector, char, int) __attribute__((nonnull (1)));

static inline char dm_get_bool_by_id(struct dm_value_table *, dm_id);
void dm_set_bool_by_id(struct dm_value_table *, dm_id, char);

/* string */
static inline const char *dm_get_string_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int         dm_set_string_by_selector(const dm_selector, char * const, int) __attribute__((nonnull (1)));

static inline const char *dm_get_string_by_id(struct dm_value_table *, dm_id);
void dm_set_string_by_id(struct dm_value_table *, dm_id, const char *);

/* binary */
static inline const binary_t *dm_get_binary_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int             dm_set_binary_by_selector(const dm_selector, binary_t * const, int) __attribute__((nonnull (1)));

static inline const binary_t *dm_get_binary_by_id(struct dm_value_table *, dm_id);
void dm_set_binary_by_id(struct dm_value_table *, dm_id, const binary_t *);

int  dm_set_binary_data_by_selector(const dm_selector, unsigned int, uint8_t * const, int) __attribute__((nonnull (1)));
void dm_set_binary_data_by_id(struct dm_value_table *, dm_id, unsigned int, const uint8_t *);

int dm_binarycmp(binary_t * const , binary_t * const);

/* enum */
static inline int  dm_get_enum_by_selector(const dm_selector)  __attribute__((nonnull (1)));
static inline int  dm_set_enum_by_selector(const dm_selector, int, int) __attribute__((nonnull (1)));

static inline int  dm_get_enum_by_id(const struct dm_value_table *, dm_id);
void dm_set_enum_by_id(struct dm_value_table *, dm_id, int);

/* counter */
static inline unsigned int dm_get_counter_by_selector(const dm_selector)  __attribute__((nonnull (1)));

static inline unsigned int dm_get_counter_by_id(const struct dm_value_table *, dm_id);
static inline unsigned int *dm_get_counter_ref_by_id(struct dm_value_table *, dm_id);
void dm_set_counter_by_id(struct dm_value_table *, dm_id, unsigned int);
static inline void dm_incr_counter_by_id(struct dm_value_table *, dm_id);
static inline void dm_decr_counter_by_id(struct dm_value_table *, dm_id);

/* int */
static inline int  dm_get_int_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int  dm_set_int_by_selector(const dm_selector, int, int) __attribute__((nonnull (1)));

static inline int  dm_get_int_by_id(const struct dm_value_table *, dm_id);
void dm_set_int_by_id(struct dm_value_table *, dm_id, int);

/* unsigned int */
static inline unsigned int  dm_get_uint_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int           dm_set_uint_by_selector(const dm_selector, unsigned int, int) __attribute__((nonnull (1)));

static inline unsigned int *dm_get_uint_ref_by_id(struct dm_value_table *, dm_id);
static inline unsigned int  dm_get_uint_by_id(const struct dm_value_table *, dm_id);
void dm_set_uint_by_id(struct dm_value_table *, dm_id, unsigned int);

static inline void dm_incr_uint_by_id(struct dm_value_table *, dm_id);
static inline void dm_decr_uint_by_id(struct dm_value_table *, dm_id);

/* int64 */
static inline int64_t dm_get_int64_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int64_t dm_set_int64_by_selector(const dm_selector, int64_t, int) __attribute__((nonnull (1)));

static inline int64_t dm_get_int64_by_id(const struct dm_value_table *, dm_id);
void dm_set_int64_by_id(struct dm_value_table *, dm_id, int64_t);

/* unsigned int64 */
static inline uint64_t  dm_get_uint64_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int       dm_set_uint64_by_selector(const dm_selector, uint64_t, int) __attribute__((nonnull (1)));

static inline uint64_t *dm_get_uint64_ref_by_id(struct dm_value_table *, dm_id);
static inline uint64_t  dm_get_uint64_by_id(const struct dm_value_table *, dm_id);
void dm_set_uint64_by_id(struct dm_value_table *, dm_id, uint64_t);

/* time_t */
static inline time_t dm_get_time_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int    dm_set_time_by_selector(const dm_selector, time_t, int) __attribute__((nonnull (1)));

static inline time_t dm_get_time_by_id(const struct dm_value_table *, dm_id);
void dm_set_time_by_id(struct dm_value_table *, dm_id, time_t);

/* ticks */
static inline ticks_t dm_get_ticks_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int     dm_set_ticks_by_selector(const dm_selector, ticks_t, int) __attribute__((nonnull (1)));

static inline ticks_t dm_get_ticks_by_id(const struct dm_value_table *, dm_id);
void dm_set_ticks_by_id(struct dm_value_table *, dm_id, ticks_t);

static inline ticks_t time2ticks(time_t t)
{
	return t * (ticks_t)10;
};

static inline ticks_t ticks2time(ticks_t t)
{
	return (t + 5) / 10;
};

ticks_t ticks(void);
ticks_t ticks_realtime(void);
ticks_t ticks2realtime(ticks_t);
time_t monotonic_time(void);

/* selector */
static inline dm_selector *dm_get_selector_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int             dm_set_selector_by_selector(const dm_selector, dm_selector *, int) __attribute__((nonnull (1)));

static inline dm_selector *dm_get_selector_by_id(const struct dm_value_table *, dm_id);
void dm_set_selector_by_id(struct dm_value_table *, dm_id, const dm_selector);

/* IPv4 Address */
static inline struct in_addr dm_get_ipv4_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int            dm_set_ipv4_by_selector(const dm_selector, struct in_addr, int) __attribute__((nonnull (1)));

static inline struct in_addr *dm_get_ipv4_ref_by_id(struct dm_value_table *, dm_id);
static inline struct in_addr  dm_get_ipv4_by_id(const struct dm_value_table *, dm_id);
void dm_set_ipv4_by_id(struct dm_value_table *, dm_id, struct in_addr);

/* IPv6 Address */
static inline struct in6_addr dm_get_ipv6_by_selector(const dm_selector) __attribute__((nonnull (1)));
static inline int            dm_set_ipv6_by_selector(const dm_selector, struct in6_addr, int) __attribute__((nonnull (1)));

static inline struct in6_addr *dm_get_ipv6_ref_by_id(struct dm_value_table *, dm_id);
static inline struct in6_addr  dm_get_ipv6_by_id(const struct dm_value_table *, dm_id);
void dm_set_ipv6_by_id(struct dm_value_table *, dm_id, struct in6_addr);

/* table */
static inline struct dm_value_table *dm_get_table_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
static inline struct dm_value_table *dm_get_table_by_id(const struct dm_value_table *, dm_id);
static inline struct dm_value_table *dm_get_table_by_index(const struct dm_value_table *, dm_id);

/* instance */
struct dm_instance                  *dm_get_instance_ref_by_selector(const dm_selector sel) __attribute__((nonnull (1)));
static inline struct dm_instance    *dm_get_instance_ref_by_id(struct dm_value_table *ift, dm_id id);

static inline struct dm_value_table *dm_get_instance_by_id(struct dm_instance *, dm_id);


/* helper */

int dm_compare_values(int, DM_VALUE *, DM_VALUE *);

/* data model walker */

typedef int walk_cb(void *, CB_type, dm_id, const struct dm_element *, const DM_VALUE);
int dm_walk_table_cb(int level, void *userData, walk_cb *cb, const struct dm_table *kw_base, struct dm_value_table *st_base) __attribute__((nonnull (3,4,5)));
int dm_walk_object_cb(int level, void *userData, walk_cb *cb, dm_id id, const struct dm_element *elem, DM_VALUE value) __attribute__((nonnull (2,3)));
int dm_walk_by_selector_cb(const dm_selector, int, void *userData, walk_cb *cb) __attribute__((nonnull (1,3)));


/*
 * static inlines
 */

/*
 * DM_VALUE manipulation
 */

void dm_free_string_value(DM_VALUE *st)
{
	if (DM_STRING(*st)) {
		DM_MEM_SUB(strlen(DM_STRING(*st)));
		free(DM_STRING(*st));
		set_DM_STRING(*st, NULL);
		DM_parity_update(*st);
	}
}

void dm_free_binary_value(DM_VALUE *st)
{
	if (DM_BINARY(*st)) {
		DM_MEM_SUB(sizeof(binary_t) + DM_BINARY(*st)->len);
		free(DM_BINARY(*st));
		set_DM_BINARY(*st, NULL);
		DM_parity_update(*st);
	}
}

void dm_free_selector_value(DM_VALUE *st)
{
	if (DM_SELECTOR(*st)) {
		free(DM_SELECTOR(*st));
		set_DM_SELECTOR(*st, NULL);
		DM_parity_update(*st);
		DM_MEM_SUB(sizeof(dm_selector));
	}
}

void dm_free_any_value(const struct dm_element *elem, DM_VALUE *st)
{
	dm_assert(elem != NULL);

	switch (elem->type) {
		case T_STR:
			dm_free_string_value(st);
			break;
		case T_BINARY:
			dm_free_binary_value(st);
			break;
		case T_SELECTOR:
			dm_free_selector_value(st);
	}
}

/*
 * type-safe get/set methods
 */

#define __DM_NOTIFY_BY_ID(ift, id)					\
	ift->values[id - 1].flags |= DV_UPDATED;			\
	DM_parity_update(ift->values[id - 1]);				\
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);

void dm_notify_by_id(struct dm_value_table *ift, dm_id id)
{
	__DM_NOTIFY_BY_ID(ift, id);
}

/*
 * access to value flags
 */
uint16_t dm_get_flags_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return ift->values[id - 1].flags;
}

/*
 * DM_VALUE
 */
DM_VALUE dm_get_by_selector(const dm_selector sel)
{
	return dm_get_any_value_by_selector(sel, T_ANY);
}

DM_VALUE *dm_get_value_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return &(ift->values[id - 1]);
}

DM_VALUE *dm_get_value_ref_by_index(struct dm_value_table *ift, dm_id idx)
{
	DM_parity_assert(ift->values[idx]);
	return &(ift->values[idx]);
}

/*
 * pointer
 */
void *dm_get_ptr_by_selector(const dm_selector sel)
{
	return DM_PTR(dm_get_any_value_by_selector(sel, T_POINTER));
}

int dm_set_ptr_by_selector(const dm_selector sel, void *ptr, int flags)
{
	return dm_set_any_value_by_selector(sel, T_POINTER, init_DM_PTR(ptr, flags));
}

void *dm_get_ptr_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_PTR(ift->values[id - 1]);
}

void dm_set_ptr_by_id(struct dm_value_table *ift, dm_id id, void *ptr)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_PTR(ift->values[id - 1], ptr);
	DM_parity_update(ift->values[id - 1]);
}

/*
 * bool
 */
char dm_get_bool_by_selector(const dm_selector sel)
{
	return DM_BOOL(dm_get_any_value_by_selector(sel, T_BOOL));
}

int dm_set_bool_by_selector(const dm_selector sel, char bool, int flags)
{
	return dm_set_any_value_by_selector(sel, T_BOOL, init_DM_BOOL(bool, flags));
}

char dm_get_bool_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_BOOL(ift->values[id - 1]);
}

/*
 * string
 */
const char *dm_get_string_by_selector(const dm_selector sel)
{
	return DM_STRING(dm_get_any_value_by_selector(sel, T_STR));
}

int dm_set_string_by_selector(const dm_selector sel, char * const s, int flags)
{
	return dm_set_any_value_by_selector(sel, T_STR, init_DM_STRING(s, flags));
}

const char *dm_get_string_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_STRING(ift->values[id - 1]);
}

/*
 * binary
 */
const binary_t *dm_get_binary_by_selector(const dm_selector sel)
{
	return DM_BINARY(dm_get_any_value_by_selector(sel, T_BINARY));
}

int dm_set_binary_by_selector(const dm_selector sel, binary_t * const s, int flags)
{
	return dm_set_any_value_by_selector(sel, T_BINARY, init_DM_BINARY(s, flags));
}

const binary_t *dm_get_binary_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_BINARY(ift->values[id - 1]);
}

/*
 * enum
 */
int dm_get_enum_by_selector(const dm_selector sel)
{
	return DM_ENUM(dm_get_any_value_by_selector(sel, T_ENUM));
}

int dm_set_enum_by_selector(const dm_selector sel, int i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_ENUM, init_DM_ENUM(i, flags));
}

int dm_get_enum_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_ENUM(ift->values[id - 1]);
}

/*
 * counter
 */
unsigned int dm_get_counter_by_selector(const dm_selector sel)
{
	return DM_UINT(dm_get_any_value_by_selector(sel, T_UINT));
}

unsigned int dm_get_counter_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT(ift->values[id - 1]);
}

unsigned int *dm_get_counter_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	return DM_UINT_REF(ift->values[id - 1]);
}

void dm_incr_counter_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) + 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

void dm_decr_counter_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) - 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

/*
 * int
 */
int dm_get_int_by_selector(const dm_selector sel)
{
	return DM_INT(dm_get_any_value_by_selector(sel, T_INT));
}

int dm_set_int_by_selector(const dm_selector sel, int i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_INT, init_DM_INT(i, flags));
}

int dm_get_int_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_INT(ift->values[id - 1]);
}

/*
 * unsigned int
 */
unsigned int dm_get_uint_by_selector(const dm_selector sel)
{
	return DM_UINT(dm_get_any_value_by_selector(sel, T_UINT));
}

int dm_set_uint_by_selector(const dm_selector sel, unsigned int i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_UINT, init_DM_UINT(i, flags));
}

unsigned int *dm_get_uint_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT_REF(ift->values[id - 1]);
}

unsigned int dm_get_uint_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT(ift->values[id - 1]);
}

void dm_incr_uint_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) + 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

void dm_decr_uint_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) - 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

/*
 * int64
 */
int64_t dm_get_int64_by_selector(const dm_selector sel)
{
	return DM_INT64(dm_get_any_value_by_selector(sel, T_INT64));
}

int64_t dm_set_int64_by_selector(const dm_selector sel, int64_t i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_INT64, init_DM_INT64(i, flags));
}

int64_t dm_get_int64_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_INT64(ift->values[id - 1]);
}

/*
 * unsigned int64
 */
uint64_t dm_get_uint64_by_selector(const dm_selector sel)
{
	return DM_UINT64(dm_get_any_value_by_selector(sel, T_UINT64));
}

int dm_set_uint64_by_selector(const dm_selector sel, uint64_t i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_UINT64, init_DM_UINT64(i, flags));
}

uint64_t *dm_get_uint64_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT64_REF(ift->values[id - 1]);
}

uint64_t dm_get_uint64_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_UINT64(ift->values[id - 1]);
}

/*
 * time_t
 */
time_t dm_get_time_by_selector(const dm_selector sel)
{
	return DM_TIME(dm_get_any_value_by_selector(sel, T_DATE));
}

int dm_set_time_by_selector(const dm_selector sel, time_t t, int flags)
{
	return dm_set_any_value_by_selector(sel, T_DATE, init_DM_TIME(t, flags));
}

time_t dm_get_time_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_TIME(ift->values[id - 1]);
}

/*
 * ticks
 */
ticks_t dm_get_ticks_by_selector(const dm_selector sel)
{
	return DM_TICKS(dm_get_any_value_by_selector(sel, T_TICKS));
}

int dm_set_ticks_by_selector(const dm_selector sel, ticks_t i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_TICKS, init_DM_TICKS(i, flags));
}

ticks_t dm_get_ticks_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_TICKS(ift->values[id - 1]);
}

/*
 * selector
 */
dm_selector *dm_get_selector_by_selector(const dm_selector sel)
{
	return DM_SELECTOR(dm_get_any_value_by_selector(sel, T_SELECTOR));
}

int dm_set_selector_by_selector(const dm_selector sel, dm_selector *s, int flags)
{
	return dm_set_any_value_by_selector(sel, T_SELECTOR, init_DM_SELECTOR(s, flags));
}

dm_selector *dm_get_selector_by_id(const struct dm_value_table *ift, dm_id id)
{
	return DM_SELECTOR(ift->values[id - 1]);
}

/*
 * IPv4 Address
 */
struct in_addr dm_get_ipv4_by_selector(const dm_selector sel)
{
	return DM_IP4(dm_get_any_value_by_selector(sel, T_IPADDR4));
}

int dm_set_ipv4_by_selector(const dm_selector sel, struct in_addr i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_IPADDR4, init_DM_IP4(i, flags));
}

struct in_addr *dm_get_ipv4_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	return DM_IP4_REF(ift->values[id - 1]);
}

struct in_addr dm_get_ipv4_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_IP4(ift->values[id - 1]);
}

/*
 * IPv6 Address
 */
struct in6_addr dm_get_ipv6_by_selector(const dm_selector sel)
{
	return DM_IP6(dm_get_any_value_by_selector(sel, T_IPADDR6));
}

int dm_set_ipv6_by_selector(const dm_selector sel, struct in6_addr i, int flags)
{
	return dm_set_any_value_by_selector(sel, T_IPADDR6, init_DM_IP6(i, flags));
}

struct in6_addr *dm_get_ipv6_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	return DM_IP6_REF(ift->values[id - 1]);
}

struct in6_addr dm_get_ipv6_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_IP6(ift->values[id - 1]);
}

/*
 * table
 */
struct dm_value_table *dm_get_table_by_selector(const dm_selector sel)
{
	return DM_TABLE(dm_get_any_value_by_selector(sel, T_ANY));
}

struct dm_value_table *dm_get_table_by_id(const struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_TABLE(ift->values[id - 1]);
}

struct dm_value_table *dm_get_table_by_index(const struct dm_value_table *ift, dm_id idx)
{
	DM_parity_assert(ift->values[idx]);
	return DM_TABLE(ift->values[idx]);
}

/*
 * instance
 */
struct dm_instance *dm_get_instance_ref_by_id(struct dm_value_table *ift, dm_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_INSTANCE(ift->values[id - 1]);
}

struct dm_value_table *dm_get_instance_by_id(struct dm_instance *ift, dm_id id)
{
	DM_VALUE *ret = dm_get_instance_node_ref_by_id(ift, id);
	if (ret)
		return DM_TABLE(*ret);
	return NULL;
}

#endif // __DM_STORE_H
