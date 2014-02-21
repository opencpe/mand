#ifndef __TR069_STORE_H
#define __TR069_STORE_H

#include "tr069.h"
#include "tr069_token.h"
#include "p_table.h"
#include "tr069_notify.h"
#include "tr069d.h"

#define TR069_MEM_ACCOUNTING

#if defined(TR069_MEM_ACCOUNTING)
extern int tr069_mem;

#define TR069_MEM_ADD(x) tr069_mem += x
#define TR069_MEM_SUB(x) tr069_mem -= x
#else
#define TR069_MEM_ADD(x) do {} while (0)
#define TR069_MEM_SUB(x) do {} while (0)
#endif

#define TR069_ID_USER_OBJECT   0x8000
#define TR069_ID_AUTO_OBJECT   0xC000
#define TR069_ID_MASK          0x3FFF

typedef enum {
	CB_element,
	CB_table_start,
	CB_table_end,
	CB_object_start,
	CB_object_end,
	CB_object_instance_start,
	CB_object_instance_end,
} CB_type;

		/* prototype for functions like tr069_get_value_by_selector_cb */
typedef DM_RESULT (*GET_BY_SELECTOR_CB)(const tr069_selector sel, int type,
					void *userData,
					DM_RESULT (*cb)(void *,
							const tr069_selector,
							const struct tr069_element *,
							const DM_VALUE));

tr069_id tr069_get_element_id_by_name(const char *name, size_t l, const struct tr069_table *kw);

#define MAX_PARAM_NAME_LEN 257

char *tr069_sel2name(const tr069_selector, char *, int size) __attribute__((nonnull (1)));

int tr069_get_element_by_selector(const tr069_selector, struct tr069_element **);

char *tr069_normalize_list(char *str);
char *tr069_add2list(char *list, char *str);
char *tr069_listdel(char *l, char *str);
int tr069_listcontains(char *l, char *str);

/* generic set functions */
DM_RESULT tr069_set_any_value_by_selector(const tr069_selector sel, int type, const DM_VALUE val) __attribute__((nonnull (1)));
DM_RESULT tr069_overwrite_any_value_by_selector(const tr069_selector sel, int type, DM_VALUE val, int slot) __attribute__((nonnull (1)));

/* generic get functions */
DM_VALUE tr069_get_any_value_by_selector(const tr069_selector sel, int type) __attribute__((nonnull (1)));

DM_RESULT tr069_set_string_value(DM_VALUE *st, const char *s);
DM_RESULT tr069_set_binary_value(DM_VALUE *st, const binary_t *b);
DM_RESULT tr069_set_binary_data(DM_VALUE *st, unsigned int len, const uint8_t *data);
DM_RESULT tr069_set_selector_value(DM_VALUE *st, const tr069_selector s);

int tr069_get_value_by_selector(const tr069_selector sel, int type, void *value) __attribute__((nonnull (1)));

DM_RESULT tr069_get_value_by_selector_cb(const tr069_selector sel, int type, void *userData,
					 DM_RESULT (*cb)(void *, const tr069_selector, const struct tr069_element *, const DM_VALUE))
	 __attribute__((nonnull (1)));

DM_RESULT tr069_set_value_by_selector(const tr069_selector sel, int type, const void *value) __attribute__((nonnull (1)));

DM_RESULT tr069_set_value_by_selector_cb(const tr069_selector sel, void *value,
				   void *userData, DM_RESULT (*cb)(void *, const tr069_selector, const struct tr069_element *,
								   const void *, DM_VALUE *))
	__attribute__((nonnull (1)));

DM_RESULT tr069_get_value_ref_by_selector_cb(const tr069_selector sel, void *value,
					     void *userData, DM_RESULT (*cb)(void *,
									     const tr069_selector,
									     const struct tr069_element *,
									     struct tr069_value_table *,
									     const void *,
									     DM_VALUE *))
	__attribute__((nonnull (1)));

struct tr069_value_table *tr069_alloc_table(const struct tr069_table *, const tr069_selector, tr069_id);
void tr069_init_table(const struct tr069_table *, struct tr069_value_table *, const tr069_selector, tr069_id);
struct tr069_value_table *tr069_extend_table(struct tr069_value_table *told, int size);

struct tr069_instance_node *tr069_add_instance_by_selector(const tr069_selector sel, tr069_id *id) __attribute__((nonnull (1)));

int tr069_add_table_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));

int tr069_del_table_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
int tr069_del_object_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));

void tr069_update_flags(void);

DM_VALUE *tr069_get_instance_node_ref_by_id(struct tr069_instance *, tr069_id);

struct tr069_instance_node *tr069_get_instance_node_by_selector(const tr069_selector) __attribute__((nonnull (1)));
struct tr069_instance_node *tr069_get_instance_node_by_id(struct tr069_instance *, tr069_id);

int tr069_mark_updated_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
const struct tr069_table *tr069_get_object_table_by_selector(tr069_selector sel) __attribute__((nonnull (1)));

/*
 * DM_VALUE memory helper
 */
static inline void tr069_free_string_value(DM_VALUE *);
static inline void tr069_free_binary_value(DM_VALUE *);
static inline void tr069_free_selector_value(DM_VALUE *);
static inline void tr069_free_any_value(const struct tr069_element *, DM_VALUE *);

/*
 * notify helper
 */
static inline void tr069_notify_by_id(struct tr069_value_table *, tr069_id);

/*
 * access to value flags
 */
static inline uint16_t tr069_get_flags_by_id(struct tr069_value_table *, tr069_id);

/*
 * type-safe get/set methods
 */

/* DM_VALUE */
static inline DM_VALUE  tr069_get_by_selector(const tr069_selector) __attribute__((nonnull (1)));

static inline DM_VALUE *tr069_get_value_ref_by_id(struct tr069_value_table *, tr069_id);
static inline DM_VALUE *tr069_get_value_ref_by_index(struct tr069_value_table *, tr069_id);

/* pointer */
static inline void *tr069_get_ptr_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int   tr069_set_ptr_by_selector(const tr069_selector, void *, int) __attribute__((nonnull (1)));

static inline void *tr069_get_ptr_by_id(struct tr069_value_table *, tr069_id);
static inline void  tr069_set_ptr_by_id(struct tr069_value_table *, tr069_id, void *);

/* bool */
static inline char tr069_get_bool_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int  tr069_set_bool_by_selector(const tr069_selector, char, int) __attribute__((nonnull (1)));

static inline char tr069_get_bool_by_id(struct tr069_value_table *, tr069_id);
void tr069_set_bool_by_id(struct tr069_value_table *, tr069_id, char);

/* string */
static inline const char *tr069_get_string_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int         tr069_set_string_by_selector(const tr069_selector, char * const, int) __attribute__((nonnull (1)));

static inline const char *tr069_get_string_by_id(struct tr069_value_table *, tr069_id);
void tr069_set_string_by_id(struct tr069_value_table *, tr069_id, const char *);

/* binary */
static inline const binary_t *tr069_get_binary_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int             tr069_set_binary_by_selector(const tr069_selector, binary_t * const, int) __attribute__((nonnull (1)));

static inline const binary_t *tr069_get_binary_by_id(struct tr069_value_table *, tr069_id);
void tr069_set_binary_by_id(struct tr069_value_table *, tr069_id, const binary_t *);

int  tr069_set_binary_data_by_selector(const tr069_selector, unsigned int, uint8_t * const, int) __attribute__((nonnull (1)));
void tr069_set_binary_data_by_id(struct tr069_value_table *, tr069_id, unsigned int, const uint8_t *);

int tr069_binarycmp(binary_t * const , binary_t * const);

/* enum */
static inline int  tr069_get_enum_by_selector(const tr069_selector)  __attribute__((nonnull (1)));
static inline int  tr069_set_enum_by_selector(const tr069_selector, int, int) __attribute__((nonnull (1)));

static inline int  tr069_get_enum_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_enum_by_id(struct tr069_value_table *, tr069_id, int);

/* counter */
static inline unsigned int tr069_get_counter_by_selector(const tr069_selector)  __attribute__((nonnull (1)));

static inline unsigned int tr069_get_counter_by_id(const struct tr069_value_table *, tr069_id);
static inline unsigned int *tr069_get_counter_ref_by_id(struct tr069_value_table *, tr069_id);
void tr069_set_counter_by_id(struct tr069_value_table *, tr069_id, unsigned int);
static inline void tr069_incr_counter_by_id(struct tr069_value_table *, tr069_id);
static inline void tr069_decr_counter_by_id(struct tr069_value_table *, tr069_id);

/* int */
static inline int  tr069_get_int_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int  tr069_set_int_by_selector(const tr069_selector, int, int) __attribute__((nonnull (1)));

static inline int  tr069_get_int_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_int_by_id(struct tr069_value_table *, tr069_id, int);

/* unsigned int */
static inline unsigned int  tr069_get_uint_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int           tr069_set_uint_by_selector(const tr069_selector, unsigned int, int) __attribute__((nonnull (1)));

static inline unsigned int *tr069_get_uint_ref_by_id(struct tr069_value_table *, tr069_id);
static inline unsigned int  tr069_get_uint_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_uint_by_id(struct tr069_value_table *, tr069_id, unsigned int);

static inline void tr069_incr_uint_by_id(struct tr069_value_table *, tr069_id);
static inline void tr069_decr_uint_by_id(struct tr069_value_table *, tr069_id);

/* int64 */
static inline int64_t tr069_get_int64_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int64_t tr069_set_int64_by_selector(const tr069_selector, int64_t, int) __attribute__((nonnull (1)));

static inline int64_t tr069_get_int64_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_int64_by_id(struct tr069_value_table *, tr069_id, int64_t);

/* unsigned int64 */
static inline uint64_t  tr069_get_uint64_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int       tr069_set_uint64_by_selector(const tr069_selector, uint64_t, int) __attribute__((nonnull (1)));

static inline uint64_t *tr069_get_uint64_ref_by_id(struct tr069_value_table *, tr069_id);
static inline uint64_t  tr069_get_uint64_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_uint64_by_id(struct tr069_value_table *, tr069_id, uint64_t);

/* time_t */
static inline time_t tr069_get_time_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int    tr069_set_time_by_selector(const tr069_selector, time_t, int) __attribute__((nonnull (1)));

static inline time_t tr069_get_time_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_time_by_id(struct tr069_value_table *, tr069_id, time_t);

/* ticks */
static inline ticks_t tr069_get_ticks_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int     tr069_set_ticks_by_selector(const tr069_selector, ticks_t, int) __attribute__((nonnull (1)));

static inline ticks_t tr069_get_ticks_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_ticks_by_id(struct tr069_value_table *, tr069_id, ticks_t);

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
static inline tr069_selector *tr069_get_selector_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int             tr069_set_selector_by_selector(const tr069_selector, tr069_selector *, int) __attribute__((nonnull (1)));

static inline tr069_selector *tr069_get_selector_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_selector_by_id(struct tr069_value_table *, tr069_id, const tr069_selector);

/* IPv4 Address */
static inline struct in_addr tr069_get_ipv4_by_selector(const tr069_selector) __attribute__((nonnull (1)));
static inline int            tr069_set_ipv4_by_selector(const tr069_selector, struct in_addr, int) __attribute__((nonnull (1)));

static inline struct in_addr *tr069_get_ipv4_ref_by_id(struct tr069_value_table *, tr069_id);
static inline struct in_addr  tr069_get_ipv4_by_id(const struct tr069_value_table *, tr069_id);
void tr069_set_ipv4_by_id(struct tr069_value_table *, tr069_id, struct in_addr);

/* table */
static inline struct tr069_value_table *tr069_get_table_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
static inline struct tr069_value_table *tr069_get_table_by_id(const struct tr069_value_table *, tr069_id);
static inline struct tr069_value_table *tr069_get_table_by_index(const struct tr069_value_table *, tr069_id);

/* instance */
struct tr069_instance                  *tr069_get_instance_ref_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
static inline struct tr069_instance    *tr069_get_instance_ref_by_id(struct tr069_value_table *ift, tr069_id id);

static inline struct tr069_value_table *tr069_get_instance_by_id(struct tr069_instance *, tr069_id);


/* helper */

int tr069_compare_values(int, DM_VALUE *, DM_VALUE *);
int tr069_walk_by_selector_cb(const tr069_selector, int, void *,
			      int (*cb)(void *, CB_type, tr069_id, const struct tr069_element *, const DM_VALUE))
	__attribute__((nonnull (1)));


/*
 * static inlines
 */

/*
 * DM_VALUE manipulation
 */

void tr069_free_string_value(DM_VALUE *st)
{
	if (DM_STRING(*st)) {
		TR069_MEM_SUB(strlen(DM_STRING(*st)));
		free(DM_STRING(*st));
		set_DM_STRING(*st, NULL);
		DM_parity_update(*st);
	}
}

void tr069_free_binary_value(DM_VALUE *st)
{
	if (DM_BINARY(*st)) {
		TR069_MEM_SUB(sizeof(binary_t) + DM_BINARY(*st)->len);
		free(DM_BINARY(*st));
		set_DM_BINARY(*st, NULL);
		DM_parity_update(*st);
	}
}

void tr069_free_selector_value(DM_VALUE *st)
{
	if (DM_SELECTOR(*st)) {
		free(DM_SELECTOR(*st));
		set_DM_SELECTOR(*st, NULL);
		DM_parity_update(*st);
		TR069_MEM_SUB(sizeof(tr069_selector));
	}
}

void tr069_free_any_value(const struct tr069_element *elem, DM_VALUE *st)
{
	dm_assert(elem != NULL);

	switch (elem->type) {
		case T_STR:
			tr069_free_string_value(st);
			break;
		case T_BINARY:
			tr069_free_binary_value(st);
			break;
		case T_SELECTOR:
			tr069_free_selector_value(st);
	}
}

/*
 * type-safe get/set methods
 */

#define __DM_NOTIFY_BY_ID(ift, id)					\
	ift->values[id - 1].flags |= DV_UPDATED;			\
	DM_parity_update(ift->values[id - 1]);				\
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);

void tr069_notify_by_id(struct tr069_value_table *ift, tr069_id id)
{
	__DM_NOTIFY_BY_ID(ift, id);
}

/*
 * access to value flags
 */
uint16_t tr069_get_flags_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return ift->values[id - 1].flags;
}

/*
 * DM_VALUE
 */
DM_VALUE tr069_get_by_selector(const tr069_selector sel)
{
	return tr069_get_any_value_by_selector(sel, T_ANY);
}

DM_VALUE *tr069_get_value_ref_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return &(ift->values[id - 1]);
}

DM_VALUE *tr069_get_value_ref_by_index(struct tr069_value_table *ift, tr069_id idx)
{
	DM_parity_assert(ift->values[idx]);
	return &(ift->values[idx]);
}

/*
 * pointer
 */
void *tr069_get_ptr_by_selector(const tr069_selector sel)
{
	return DM_PTR(tr069_get_any_value_by_selector(sel, T_POINTER));
}

int tr069_set_ptr_by_selector(const tr069_selector sel, void *ptr, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_POINTER, init_DM_PTR(ptr, flags));
}

void *tr069_get_ptr_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_PTR(ift->values[id - 1]);
}

void tr069_set_ptr_by_id(struct tr069_value_table *ift, tr069_id id, void *ptr)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_PTR(ift->values[id - 1], ptr);
	DM_parity_update(ift->values[id - 1]);
}

/*
 * bool
 */
char tr069_get_bool_by_selector(const tr069_selector sel)
{
	return DM_BOOL(tr069_get_any_value_by_selector(sel, T_BOOL));
}

int tr069_set_bool_by_selector(const tr069_selector sel, char bool, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_BOOL, init_DM_BOOL(bool, flags));
}

char tr069_get_bool_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_BOOL(ift->values[id - 1]);
}

/*
 * string
 */
const char *tr069_get_string_by_selector(const tr069_selector sel)
{
	return DM_STRING(tr069_get_any_value_by_selector(sel, T_STR));
}

int tr069_set_string_by_selector(const tr069_selector sel, char * const s, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_STR, init_DM_STRING(s, flags));
}

const char *tr069_get_string_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_STRING(ift->values[id - 1]);
}

/*
 * binary
 */
const binary_t *tr069_get_binary_by_selector(const tr069_selector sel)
{
	return DM_BINARY(tr069_get_any_value_by_selector(sel, T_BINARY));
}

int tr069_set_binary_by_selector(const tr069_selector sel, binary_t * const s, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_BINARY, init_DM_BINARY(s, flags));
}

const binary_t *tr069_get_binary_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_BINARY(ift->values[id - 1]);
}

/*
 * enum
 */
int tr069_get_enum_by_selector(const tr069_selector sel)
{
	return DM_ENUM(tr069_get_any_value_by_selector(sel, T_ENUM));
}

int tr069_set_enum_by_selector(const tr069_selector sel, int i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_ENUM, init_DM_ENUM(i, flags));
}

int tr069_get_enum_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_ENUM(ift->values[id - 1]);
}

/*
 * counter
 */
unsigned int tr069_get_counter_by_selector(const tr069_selector sel)
{
	return DM_UINT(tr069_get_any_value_by_selector(sel, T_UINT));
}

unsigned int tr069_get_counter_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT(ift->values[id - 1]);
}

unsigned int *tr069_get_counter_ref_by_id(struct tr069_value_table *ift, tr069_id id)
{
	return DM_UINT_REF(ift->values[id - 1]);
}

void tr069_incr_counter_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) + 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

void tr069_decr_counter_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) - 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

/*
 * int
 */
int tr069_get_int_by_selector(const tr069_selector sel)
{
	return DM_INT(tr069_get_any_value_by_selector(sel, T_INT));
}

int tr069_set_int_by_selector(const tr069_selector sel, int i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_INT, init_DM_INT(i, flags));
}

int tr069_get_int_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_INT(ift->values[id - 1]);
}

/*
 * unsigned int
 */
unsigned int tr069_get_uint_by_selector(const tr069_selector sel)
{
	return DM_UINT(tr069_get_any_value_by_selector(sel, T_UINT));
}

int tr069_set_uint_by_selector(const tr069_selector sel, unsigned int i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_UINT, init_DM_UINT(i, flags));
}

unsigned int *tr069_get_uint_ref_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT_REF(ift->values[id - 1]);
}

unsigned int tr069_get_uint_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT(ift->values[id - 1]);
}

void tr069_incr_uint_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) + 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

void tr069_decr_uint_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], DM_UINT(ift->values[id - 1]) - 1);
	DM_parity_update(ift->values[id - 1]);
	notify(-1, ift->id, id, ift->values[id - 1], NOTIFY_CHANGE);
}

/*
 * int64
 */
int64_t tr069_get_int64_by_selector(const tr069_selector sel)
{
	return DM_INT64(tr069_get_any_value_by_selector(sel, T_INT64));
}

int64_t tr069_set_int64_by_selector(const tr069_selector sel, int64_t i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_INT64, init_DM_INT64(i, flags));
}

int64_t tr069_get_int64_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_INT64(ift->values[id - 1]);
}

/*
 * unsigned int64
 */
uint64_t tr069_get_uint64_by_selector(const tr069_selector sel)
{
	return DM_UINT64(tr069_get_any_value_by_selector(sel, T_UINT64));
}

int tr069_set_uint64_by_selector(const tr069_selector sel, uint64_t i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_UINT64, init_DM_UINT64(i, flags));
}

uint64_t *tr069_get_uint64_ref_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_UINT64_REF(ift->values[id - 1]);
}

uint64_t tr069_get_uint64_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	return DM_UINT64(ift->values[id - 1]);
}

/*
 * time_t
 */
time_t tr069_get_time_by_selector(const tr069_selector sel)
{
	return DM_TIME(tr069_get_any_value_by_selector(sel, T_DATE));
}

int tr069_set_time_by_selector(const tr069_selector sel, time_t t, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_DATE, init_DM_TIME(t, flags));
}

time_t tr069_get_time_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_TIME(ift->values[id - 1]);
}

/*
 * ticks
 */
ticks_t tr069_get_ticks_by_selector(const tr069_selector sel)
{
	return DM_TICKS(tr069_get_any_value_by_selector(sel, T_TICKS));
}

int tr069_set_ticks_by_selector(const tr069_selector sel, ticks_t i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_TICKS, init_DM_TICKS(i, flags));
}

ticks_t tr069_get_ticks_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_TICKS(ift->values[id - 1]);
}

/*
 * selector
 */
tr069_selector *tr069_get_selector_by_selector(const tr069_selector sel)
{
	return DM_SELECTOR(tr069_get_any_value_by_selector(sel, T_SELECTOR));
}

int tr069_set_selector_by_selector(const tr069_selector sel, tr069_selector *s, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_SELECTOR, init_DM_SELECTOR(s, flags));
}

tr069_selector *tr069_get_selector_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	return DM_SELECTOR(ift->values[id - 1]);
}

/*
 * IPv4 Address
 */
struct in_addr tr069_get_ipv4_by_selector(const tr069_selector sel)
{
	return DM_IP4(tr069_get_any_value_by_selector(sel, T_IPADDR4));
}

int tr069_set_ipv4_by_selector(const tr069_selector sel, struct in_addr i, int flags)
{
	return tr069_set_any_value_by_selector(sel, T_IPADDR4, init_DM_IP4(i, flags));
}

struct in_addr *tr069_get_ipv4_ref_by_id(struct tr069_value_table *ift, tr069_id id)
{
	return DM_IP4_REF(ift->values[id - 1]);
}

struct in_addr tr069_get_ipv4_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_IP4(ift->values[id - 1]);
}

/*
 * table
 */
struct tr069_value_table *tr069_get_table_by_selector(const tr069_selector sel)
{
	return DM_TABLE(tr069_get_any_value_by_selector(sel, T_ANY));
}

struct tr069_value_table *tr069_get_table_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_TABLE(ift->values[id - 1]);
}

struct tr069_value_table *tr069_get_table_by_index(const struct tr069_value_table *ift, tr069_id idx)
{
	DM_parity_assert(ift->values[idx]);
	return DM_TABLE(ift->values[idx]);
}

/*
 * instance
 */
struct tr069_instance *tr069_get_instance_ref_by_id(struct tr069_value_table *ift, tr069_id id)
{
	DM_parity_assert(ift->values[id - 1]);
	return DM_INSTANCE(ift->values[id - 1]);
}

struct tr069_value_table *tr069_get_instance_by_id(struct tr069_instance *ift, tr069_id id)
{
	DM_VALUE *ret = tr069_get_instance_node_ref_by_id(ift, id);
	if (ret)
		return DM_TABLE(*ret);
	return NULL;
}

#endif // __TR069_STORE_H
