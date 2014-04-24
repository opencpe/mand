/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_TOKEN_H
#define __DM_TOKEN_H

#if !defined(NDEBUG)
#define DEBUG 1
#define TYPE_SAFETY_TEST
#define MEMORY_PARITY
#define STRUCT_MAGIC
#endif

#include "dm_assert.h"

#include "config.h"

#include <time.h>
#include <inttypes.h>
#include <string.h>
#include <netinet/ip.h>

#include "dm.h"

enum {
	T_NONE      = 0x00,
	T_ANY       = 0xFF,

	T_TOKEN     = 0x01,
	T_OBJECT,
	T_INSTANCE,

	T_POINTER   = 0x20,

	T_ELEMENT   = 0x40,
	T_UINT,
	T_INT,
	T_BOOL,
	T_STR,
	T_BINARY,
	T_BASE64,
	T_DATE,
	T_COUNTER,
	T_ENUM,
	T_SELECTOR,
	T_IPADDR4,
	T_IPADDR6,
	T_INT64,
	T_UINT64,
	T_TICKS,
};

enum {
	__F_READ,
	__F_WRITE,
	__F_GET,
	__F_SET,
	__F_ADD,
	__F_DEL,
	__F_SYSTEM,
	__F_INDEX,
	__F_CHANGED,
	__F_ACS_NTFY,
	__F_ACS_NO_NTFY,
	__F_INTERNAL,
	__F_MAP_ID,
	__F_VERSION,
	__F_DATETIME,
	__F_ARRAY,
};

#define F_READ		(1 << __F_READ)
#define F_WRITE		(1 << __F_WRITE)
#define F_GET		(1 << __F_GET)
#define F_SET		(1 << __F_SET)
#define F_ADD		(1 << __F_ADD)
#define F_DEL		(1 << __F_DEL)
#define F_SYSTEM	(1 << __F_SYSTEM)
#define F_INDEX		(1 << __F_INDEX)
#define F_ACS_NTFY	(1 << __F_ACS_NTFY)
#define F_ACS_NO_NTFY	(1 << __F_ACS_NO_NTFY)
#define F_INTERNAL	(1 << __F_INTERNAL)
#define F_MAP_ID	(1 << __F_MAP_ID)
#define F_VERSION	(1 << __F_VERSION)
#define F_DATETIME	(1 << __F_DATETIME)
#define F_ARRAY		(1 << __F_ARRAY)

enum {
	__IDX_UNIQUE = 0,
};

#define IDX_UNIQUE	(1 << __IDX_UNIQUE)

enum {
	NO_NOTIFY = 0,
	PASSIVE_NOTIFY,
	ACTIVE_NOTIFY,
};

typedef enum {
	DM_OK = 0,
	DM_ERROR,
	DM_OOM,
	DM_INVALID_TYPE,
	DM_INVALID_VALUE,
	DM_VALUE_NOT_FOUND,
 	DM_FILE_NOT_FOUND,
} DM_RESULT;

#define DM_SELECTOR_LEN    16
typedef uint16_t dm_id;
typedef dm_id dm_selector[DM_SELECTOR_LEN];
#define DM_ERR UINT16_MAX

struct dm_value_table;
struct dm_instance_tree;
struct dm_instance_node;

struct dm_instance {
	struct dm_instance_tree *instance;
};

#define EPOCH 12307680000           // 2009-01-01 00:00:00.0
#define PRItick PRIi64
typedef int64_t ticks_t;

enum {
	__DV_NOTIFY,
	__DV_UPDATE_PENDING,
	__DV_UPDATED,
	__DV_DELETED,
};

#define DV_NONE            0
#define DV_NOTIFY          (1 << __DV_NOTIFY)
#define DV_UPDATE_PENDING  (1 << __DV_UPDATE_PENDING)
#define DV_UPDATED         (1 << __DV_UPDATED)
#define DV_DELETED         (1 << __DV_DELETED)

typedef struct {
	unsigned int len;
	uint8_t      data[];
} binary_t;

#define MAGIC_TYPE unsigned int
#define TABLE_MAGIC          0xDEADBEAF
#define INSTANCE_MAGIC       0xFDEADBEA
#define NODE_MAGIC           0xAFDEADBE
#define INDEX_MAGIC          0xEAFDEADB
#define INDEX_FREE_MAGIC     0xBEAFDEAD

#define TABLE_KILL_MAGIC          0xFAEBDAED
#define INSTANCE_KILL_MAGIC       0xDFAEBDAE
#define NODE_KILL_MAGIC           0xEDFAEBDA
#define INDEX_KILL_MAGIC          0xAEDFAEBD

#if defined(STRUCT_MAGIC)
#define STRUCT_MAGIC_START MAGIC_TYPE __struct_magic_start;
#define STRUCT_MAGIC_END   MAGIC_TYPE __struct_magic_end;

#define init_struct_magic_start(obj, m) (obj)->__struct_magic_start = (m)
#define init_struct_magic_end(obj, m)   (obj)->__struct_magic_end = (m)
#define init_struct_magic(obj, m)       (obj)->__struct_magic_start = (obj)->__struct_magic_end = (m)

#define assert_struct_magic_start(obj, m) if (obj) dm_assert_magic(obj, (obj)->__struct_magic_start, m)
#define assert_struct_magic_end(obj, m)   if (obj) dm_assert_magic(obj, (obj)->__struct_magic_end, m)
#define assert_struct_magic(obj, m)					\
	do {								\
		if (obj) {						\
			dm_assert_magic(obj, (obj)->__struct_magic_start, m); \
			dm_assert_magic(obj, (obj)->__struct_magic_end, m); \
		}							\
	} while (0)
#else
#define STRUCT_MAGIC_START
#define STRUCT_MAGIC_END

#define init_struct_magic_start(obj, m) do { } while (0)
#define init_struct_magic_end(obj, m)   do { } while (0)
#define init_struct_magic(obj, m)       do { } while (0)

#define assert_struct_magic_start(obj, m) do { } while (0)
#define assert_struct_magic_end(obj, m)   do { } while (0)
#define assert_struct_magic(obj, m)       do { } while (0)
#endif

typedef struct {
	union {
		void                     *ptr;
		int                      int_val;
		unsigned int             uint_val;
		int                      bool_val;
		time_t                   time_val;
		struct in_addr           ip4_val;
		struct in6_addr          ip6_val;
		char                     *string;
		binary_t                 *binary;
		dm_selector           *selector;
		struct dm_value_table *table;
		struct dm_instance    instance;
		struct dm_instance_node *node;
		int64_t                  int64_val;
		uint64_t                 uint64_val;
		ticks_t                  ticks_val;
	} _v;
	uint32_t notify;
	uint16_t flags;
#if defined(TYPE_SAFETY_TEST)
	unsigned short type;
#endif
#if defined(MEMORY_PARITY)
	uint32_t          parity __attribute__ ((aligned (4)));
#endif
} DM_VALUE;

#if defined(MEMORY_PARITY)
#if defined(TYPE_SAFETY_TEST)
#define _get_DM_parity_flags(val) ((val).flags | (val).type << 16)
#else
#define _get_DM_parity_flags(val) (val).flags
#endif
#define _get_DM_parity(val) (((uint32_t *)&(val))[0] ^ ((uint32_t *)&(val))[1] ^ (val).notify ^ _get_DM_parity_flags(val))
#define DM_parity_update(val) (val).parity = _get_DM_parity(val)
#define DM_parity_invalidate(val) (val).parity = _get_DM_parity(val) ^ 0xffffffff;
#define DM_parity_assert(val)											\
	do {													\
		if (unlikely((val).parity != _get_DM_parity(val)))						\
			__dm_parity_assert_fail(_get_DM_parity(val), (val).parity, __LINE__, __FUNCTION__);	\
	} while (0)
#else
#define DM_parity_update(val) do { } while (0)
#define DM_parity_invalidate(val) do { } while (0)
#define DM_parity_assert(val) do { } while (0)
#endif


#if defined(TYPE_SAFETY_TEST)
#define DM_type_assert(val, t)							       \
	do {									       \
		if (unlikely((val).type != T_NONE && (val).type != (t)))	       \
			__dm_type_assert_fail(#t, (val).type, __LINE__, __FUNCTION__); \
	} while (0)

#define _set_DM_type(val, t)  (val).type = t
#define _init_DM_type(t)  .type = t
#else
#define DM_type_assert(val, t) do { } while (0)
#define _set_DM_type(val, t) do { } while (0)
#define _init_DM_type(t)
#endif

#define DM_PTR(val)             ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_POINTER); _v._v.ptr; })
#define DM_PTR_REF(val)         ({ DM_type_assert(val, T_POINTER); &(val)._v.ptr; })
#define set_DM_PTR(val, t)      { (val)._v.ptr = (void *)t; _set_DM_type(val, T_POINTER); }
#define init_DM_PTR(n, f)       (DM_VALUE){ ._v.ptr = (void *)n, .flags = f, _init_DM_type(T_POINTER) }

#define DM_INT(val)             ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_INT); _v._v.int_val; })
#define DM_INT_REF(val)         ({ DM_type_assert(val, T_INT); &(val)._v.int_val; })
#define set_DM_INT(val, t)      { (val)._v.int_val = t; _set_DM_type(val, T_INT); }
#define init_DM_INT(n, f)       (DM_VALUE){ ._v.int_val = n, .flags = f, _init_DM_type(T_INT) }

#define DM_UINT(val)            ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_UINT); _v._v.uint_val; })
#define DM_UINT_REF(val)        ({ DM_type_assert(val, T_UINT); &(val)._v.uint_val; })
#define set_DM_UINT(val, t)     { (val)._v.uint_val = t; _set_DM_type(val, T_UINT); }
#define init_DM_UINT(n, f)      (DM_VALUE){ ._v.uint_val = n, .flags = f, _init_DM_type(T_UINT) }

#define DM_ENUM(val)             ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_ENUM); _v._v.int_val; })
#define set_DM_ENUM(val, t)      { (val)._v.int_val = t; _set_DM_type(val, T_ENUM); }
#define init_DM_ENUM(n, f)      (DM_VALUE){ ._v.int_val = n, .flags = f, _init_DM_type(T_ENUM) }

#define DM_BOOL(val)            ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_BOOL); _v._v.bool_val; })
#define set_DM_BOOL(val, t)     { (val)._v.bool_val = t; _set_DM_type(val, T_BOOL); }
#define init_DM_BOOL(n, f)      (DM_VALUE){ ._v.bool_val = n, .flags = f, _init_DM_type(T_BOOL) }

#define DM_TIME(val)            ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_DATE); _v._v.time_val; })
#define DM_TIME_REF(val)        ({ DM_type_assert(val, T_DATE); &(val)._v.time_val; })
#define set_DM_TIME(val, t)     { (val)._v.time_val = t; _set_DM_type(val, T_DATE); }
#define init_DM_TIME(n, f)      (DM_VALUE){ ._v.time_val = n, .flags = f, _init_DM_type(T_DATE) }

#define DM_STRING(val)          ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_STR); _v._v.string; })
#define set_DM_STRING(val, t)   { (val)._v.string = t; _set_DM_type(val, T_STR); }
#define init_DM_STRING(n, f)    (DM_VALUE){ ._v.string = n, .flags = f, _init_DM_type(T_STR) }

#define DM_BINARY(val)          ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_BINARY); _v._v.binary; })
#define set_DM_BINARY(val, t)   { (val)._v.binary = t; _set_DM_type(val, T_BINARY); }
#define init_DM_BINARY(n, f)    (DM_VALUE){ ._v.binary = n, .flags = f, _init_DM_type(T_BINARY) }

#define DM_SELECTOR(val)        ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_SELECTOR); _v._v.selector; })
#define set_DM_SELECTOR(val, t) { (val)._v.selector = t; _set_DM_type(val, T_SELECTOR); }
#define init_DM_SELECTOR(n, f)  (DM_VALUE){ ._v.selector = n, .flags = f, _init_DM_type(T_SELECTOR) }

#define DM_IP4(val)             ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_IPADDR4); _v._v.ip4_val; })
#define DM_IP4_REF(val)         ({ DM_type_assert(val, T_IPADDR4); &(val)._v.ip4_val; })
#define set_DM_IP4(val, t)      { (val)._v.ip4_val = t; _set_DM_type(val, T_IPADDR4); }
#define init_DM_IP4(n, f)       (DM_VALUE){ ._v.ip4_val = n, .flags = f, _init_DM_type(T_IPADDR4) }

#define DM_IP6(val)             ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_IPADDR6); _v._v.ip6_val; })
#define DM_IP6_REF(val)         ({ DM_type_assert(val, T_IPADDR6); &(val)._v.ip6_val; })
#define set_DM_IP6(val, t)      { (val)._v.ip6_val = t; _set_DM_type(val, T_IPADDR6); }
#define init_DM_IP6(n, f)       (DM_VALUE){ ._v.ip6_val = n, .flags = f, _init_DM_type(T_IPADDR6) }

#define DM_TABLE(val)           ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_TOKEN); assert_struct_magic_start(_v._v.table, TABLE_MAGIC); _v._v.table; })
#define DM_TABLE_REF(val)       ({ DM_type_assert(val, T_TOKEN); assert_struct_magic_start((val)._v.table, TABLE_MAGIC); &(val)._v.table; })
#define set_DM_TABLE(val, t)    { assert_struct_magic_start(t, TABLE_MAGIC); (val)._v.table = t; _set_DM_type(val, T_TOKEN); }

#define DM_INSTANCE(val)        ({ DM_type_assert(val, T_OBJECT); &(val)._v.instance; })
#define DM_NODE(val)            ({ DM_type_assert(val, T_INSTANCE); assert_struct_magic((val)._v.node, NODE_MAGIC); (val)._v.node; })
#define init_DM_NODE(n, f)      (DM_VALUE){ ._v.node = n, .flags = f, _init_DM_type(T_INSTANCE) }

#define DM_INT64(val)           ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_INT64); _v._v.int64_val; })
#define DM_INT64_REF(val)       ({ DM_type_assert(val, T_INT64); &(val)._v.int64_val; })
#define set_DM_INT64(val, t)    { (val)._v.int64_val = t; _set_DM_type(val, T_INT64); }
#define init_DM_INT64(n, f)     (DM_VALUE){ ._v.int64_val = n, .flags = f, _init_DM_type(T_INT64) }

#define DM_UINT64(val)          ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_UINT64); _v._v.uint64_val; })
#define DM_UINT64_REF(val)      ({ DM_type_assert(val, T_UINT64); &(val)._v.uint64_val; })
#define set_DM_UINT64(val, t)   { (val)._v.uint64_val = t; _set_DM_type(val, T_UINT64); }
#define init_DM_UINT64(n, f)    (DM_VALUE){ ._v.uint64_val = n, .flags = f, _init_DM_type(T_UINT64) }

#define DM_TICKS(val)           ({ const DM_VALUE _v = (val); DM_type_assert(_v, T_TICKS); _v._v.ticks_val; })
#define DM_TICKS_REF(val)       ({ DM_type_assert(val, T_TICKS); &(val)._v.ticks_val; })
#define set_DM_TICKS(val, t)    { (val)._v.ticks_val = t; _set_DM_type(val, T_TICKS); }
#define init_DM_TICKS(n, f)     (DM_VALUE){ ._v.ticks_val = n, .flags = f, _init_DM_type(T_TICKS) }

struct dm_value_table {
	STRUCT_MAGIC_START
	dm_selector    id;
	DM_VALUE          values[0];
};

struct dm_instance_node {
	STRUCT_MAGIC_START
	DM_VALUE          table;
	dm_id          instance;
	int               idm;

	struct dm_instance_tree *root;
	STRUCT_MAGIC_END
};

#if !defined(offsetof)
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif
#define generic_struct_cast(type, member, var) (type *)(((unsigned char *)var) - offsetof(type, member))

#define cast_table2node(t) (((struct dm_instance_node *)(t)) - 1)
#define cast_node_table_ref2node(t) generic_struct_cast(struct dm_instance_node, table, t)

struct dm_token;
struct dm_element;
struct dm_table;

struct dm_value_fkts {
	int (*validate)(const struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE, unsigned int *, char **);
	DM_VALUE (*get)(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE);
	int (*set)(struct dm_value_table *,dm_id, const struct dm_element *, DM_VALUE *, DM_VALUE);
};

struct dm_instance_fkts {
	void (*add)(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *);
	void (*del)(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *);
};

struct dm_int_limits {
	int min;
	int max;
};

struct dm_enum {
	int  cnt;
	char *data;
};

struct index_definition {
	int size;
	struct {
		unsigned short flags;
		unsigned short type;
		unsigned short element;
	} idx[];
};

struct dm_element {
	char *key;
	unsigned short type;
	uint16_t flags;
	uint16_t action;
	union {
		const struct dm_value_fkts value;
		const struct dm_instance_fkts instance;
	} fkts;
	union {
		struct {
			const struct dm_table *table;
			unsigned int max;
		} t;
		const struct dm_int_limits l;
		const struct dm_enum e;
		dm_id counter_ref;
	} u;
};

struct dm_token {
	int cntr[4];
	const struct dm_element *element;
};

#if DEBUG
#define TABLE_NAME(x)     .name = x,
#else
#define TABLE_NAME(x)
#endif

struct dm_table {
#if DEBUG
	char *name;
#endif
	const struct index_definition *index;
	int size;
	struct dm_element table[];
};

extern const struct dm_table dm_root;
extern struct dm_value_table *dm_value_store;

extern time_t igd_parameters_tstamp;
extern int mngt_srv_url_change;

int dm_enum2int(const struct dm_enum *, const char *);
const char *dm_int2enum(const struct dm_enum *, int);

int dm_selcmp(const dm_selector s1, const dm_selector s2, size_t len);

static inline size_t dm_sellen(const dm_selector sel) __attribute__((nonnull (1)));
static inline void dm_selcpy(dm_selector s1, const dm_selector s2) __attribute__((nonnull (1,2)));
static inline void dm_selcat(dm_selector sel, dm_id id) __attribute__((nonnull (1)));

size_t dm_sellen(const dm_selector sel)
{
	int i;

	for (i = 0; i < DM_SELECTOR_LEN && sel[i]; i++)
		;

	return i;
}

void dm_selcpy(dm_selector s1, const dm_selector s2)
{
	memcpy(s1, s2, sizeof(dm_selector));
}

void dm_selcat(dm_selector sel, dm_id id)
{
	for (int i = 0; i < DM_SELECTOR_LEN; i++) {
		if (sel[i] == 0) {
			sel[i] = id;
			if (i + 1 < DM_SELECTOR_LEN)
				sel[i + 1] = 0;
			break;
		}
	}
}
#endif /* __DM_TABLE_H */
