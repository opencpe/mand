/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <dm_assert.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "compiler.h"

#include "dm.h"
#include "dm_token.h"
#include "dm_index.h"
#include "dm_store.h"
#include "dm_notify.h"
#include "dm_action.h"
#include "dm_store_priv.h"
#include "dm_serialize.h"

//#define SDEBUG
#include "debug.h"

extern const struct dm_table keyword_2_tab;

struct dm_value_table *dm_value_store;

#if defined(DM_MEM_ACCOUNTING)
int dm_mem = 0;
#endif

#define tickssub(a, b, result)						\
	do {								\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
		(result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;	\
		if ((result)->tv_nsec < 0) {				\
			--(result)->tv_sec;				\
			(result)->tv_nsec += 1000000000;		\
		}							\
	} while (0)


ticks_t ticks(void)
{
	struct timespec ts;

	dm_assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

	return ts.tv_sec * (ticks_t)10 + (ts.tv_nsec / 100000000);
}

ticks_t ticks_realtime(void)
{
	struct timespec ts;

	dm_assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);

	return ts.tv_sec * (ticks_t)10 + (ts.tv_nsec / 100000000);
}
time_t monotonic_time(void)
{
	struct timespec ts;

	dm_assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);

	return ts.tv_sec;
}

ticks_t ticks2realtime(ticks_t t)
{
	struct timespec mts, rts, ts;
	ticks_t base;

	dm_assert(clock_gettime(CLOCK_REALTIME, &rts) == 0);
	dm_assert(clock_gettime(CLOCK_MONOTONIC, &mts) == 0);

	tickssub(&rts, &mts, &ts);
	base = ts.tv_sec * (ticks_t)10 + (ts.tv_nsec / 100000000);

	return base + t;
}

char *dm_normalize_list(char *str)
{
	char *s, *p;

	p = s = str;

	while (*s) {

		/* skip spaces and commas */
		for (; *s && (isspace(*s) || *s == ','); s++)
			;

		if (*s && p != str)
			*p++ = ',';

		/* find end of current entry */
		for (; *s && !(isspace(*s) || *s == ','); s++)
			*p++ = *s;
	}
	*p = '\0';

	return str;
}

char *dm_add2list(char *list, char *str)
{
	char *l;

	if (!list)
		l = strdup(str);
	else {
		char *p;
		int l1 = strlen(list);
		int l2 = strlen(str) + 1;

		l = malloc(l1 + 1 + l2);
		if (!l)
			return NULL;
		memcpy(l, list, l1);
		p = l + l1;

		*p++ = ',';
		memcpy(p, str, l2);
	}

	return l;
}

char *dm_listdel(char *l, char *str)
{
	int l1 = strlen(str);

	while (l && *l) {
		char *e;
		int l2;

		e = strchr(l, ',');
		if (e)
			l2 = e - l;
		else
			l2 = strlen(l);

		if (l1 == l2 && strncmp(str, l, l1) == 0) {
			/* found it */

			if (e) {
				/* carve it out */
				memmove(l, e + 1, strlen(e + 1) + 1);
			} else if (l == str)
				*l = '\0';
			else
				*(l - 1) = '\0';

			break;
		}
		l = e;
		if (e) /* skip comma */
			l++;
	}
	return l;
}

int dm_listcontains(char *l, char *str)
{
	int l1 = strlen(str);

	while (l && *l) {
		char *e;
		int l2;

		e = strchr(l, ',');
		if (e)
			l2 = e - l;
		else
			l2 = strlen(l);

		if (l1 == l2 && strncmp(str, l, l1) == 0)
			return 1;
		l = e;
		if (e) /* skip comma */
			l++;
	}
	return 0;
}

int dm_enum2int(const struct dm_enum *e, const char *id)
{
	int i, l;
	char *d;

	if (!e)
		return -1;

	debug(": id=%s\n", id);
	d = e->data;
	for (i = 0; i < e->cnt; i++, d = d + l + 1) {
		l = strlen(d);
		debug(": testing: %s\n", d);
		if (strcmp(d, id) == 0) {
			debug(": returning: %d\n", i);
			return i;
		}
	}
	return -1;
}

const char *dm_int2enum(const struct dm_enum *e, int id)
{
	int i;
	char *d;

	if (!e || id < 0 || id >= e->cnt)
		return "";

	d = e->data;
	for (i = 0; i < id; i++, d = d + strlen(d) + 1)
		;

	debug(": id=%d, ret=%s\n", id, d);

	return d;
}

char *dm_sel2name(const dm_selector sel, char *s, int size)
{
	int i;
	int t = T_TOKEN;
	char *n;
	const struct dm_table *kw = &dm_root;

	if (!s)
		return NULL;
	memset(s, 0, size);
	n = s;

	for (i = 0; i < DM_SELECTOR_LEN && sel[i] && kw && size > 1; i++) {
		int l;
		int idx = sel[i] - 1;

		if (i != 0) {
			*n++ = '.'; size--;
		}

		if (t == T_OBJECT) {
			l = snprintf(n, size, "%hu", sel[i]);
			t = T_TOKEN;
		} else {
			if (idx >= kw->size)
				return NULL;

			t = kw->table[idx].type;
			l = strlen(kw->table[idx].key);
			if (l >= size)
				return NULL;

			strcat(n, kw->table[idx].key);
			if (t == T_TOKEN || t == T_OBJECT)
				kw = kw->table[idx].u.t.table;
			else
				break;
		}
		n += l;
		size -= l;
	}
	return s;
}

int dm_get_element_by_selector(const dm_selector sel,
				  struct dm_element **elm)
{
	int t = T_TOKEN;
	const struct dm_table *kw = &dm_root;

	for (int i = 0; i < DM_SELECTOR_LEN && sel[i] && kw; i++) {
		int idx = sel[i] - 1;

		if (t == T_OBJECT) {
			t = T_TOKEN;
		} else {
			if (idx >= kw->size)
				return T_NONE;

			*elm = (struct dm_element *)(kw->table + idx);
			t = (*elm)->type;

			if (t == T_TOKEN || t == T_OBJECT)
				kw = (*elm)->u.t.table;
			else
				break;
		}
	}

	return t;
}

void dm_init_table(const struct dm_table *kwt, struct dm_value_table *t,  const dm_selector base, dm_id id)
{
	int size = kwt->size;

	dm_selcpy(t->id, base);
	dm_selcat(t->id, id);

	init_struct_magic_start(t, TABLE_MAGIC);
	for (int i = 0; i < size; i++) {
		t->values[i].notify = notify_default(&kwt->table[i]);
#if defined(TYPE_SAFETY_TEST)
		t->values[i].type = kwt->table[i].type;
#endif

		switch (kwt->table[i].type) {
		case T_COUNTER: {
#if defined(TYPE_SAFETY_TEST)
			t->values[i].type = T_UINT;
#endif

			dm_id ref = kwt->table[i].u.counter_ref;

			if (!ref) {
				debug("(): counter %s with zero ref", kwt->table[i].key);
				break;
			}

			if (!DM_INSTANCE(t->values[ref - 1])->instance) {
				debug("(): alloc instance %s (%d) from counter %s (%d)",
				      kwt->table[ref - 1].key, ref, kwt->table[i].key, i + 1);
				if (!dm_alloc_instance(&kwt->table[ref - 1], DM_INSTANCE(t->values[ref - 1])))
					break;
			}

			dm_instance_set_counter(DM_INSTANCE(t->values[ref - 1]), t, i + 1);
			debug("(): setting counter to %s (%d) on instance %s (%d)",
			      kwt->table[i].key, i + 1, kwt->table[ref - 1].key, ref);
			break;
		}
		case T_TOKEN:
			set_DM_TABLE(t->values[i], dm_alloc_table(kwt->table[i].u.t.table, t->id, i + 1));
			break;

		case T_OBJECT:
			if (!DM_INSTANCE(t->values[i])->instance) {
				debug("(): alloc instance %s (%d)", kwt->table[i].key, i + 1);
				dm_alloc_instance(&kwt->table[i], DM_INSTANCE(t->values[i]));
			}
			break;

#if defined(TYPE_SAFETY_TEST)
		case T_BASE64:
			t->values[i].type = T_BINARY;
			break;
#endif

		default:
			break;
		}
		DM_parity_update(t->values[i]);
	}
}

struct dm_value_table *dm_alloc_table(const struct dm_table *kwt, const dm_selector base, dm_id id)
{
	dm_assert(kwt);
	struct dm_value_table *t;

	int size = kwt->size;

	t = malloc(sizeof(struct dm_value_table) + sizeof(DM_VALUE) * size);
	if (!t)
		return NULL;

	DM_MEM_ADD(sizeof(struct dm_value_table) + sizeof(DM_VALUE) * size);
	memset(t, 0, sizeof(struct dm_value_table) + sizeof(DM_VALUE) * size);

	dm_init_table(kwt, t, base, id);

	return t;
}

static void dm_free_table(const struct dm_table *kwt, struct dm_value_table *st)
{
	dm_assert(kwt != 0);
	dm_assert(st != NULL);
	assert_struct_magic_start(st, TABLE_MAGIC);

	init_struct_magic_start(st, TABLE_KILL_MAGIC);

	DM_MEM_SUB(sizeof(struct dm_value_table) + sizeof(DM_VALUE) * (kwt->size));
	free(st);
}

struct dm_instance_node *dm_add_instance(const struct dm_element *kw,
					       struct dm_instance *base,
					       const dm_selector basesel,
					       dm_id id)
{
	dm_assert(base);

	struct dm_element_ref baseref;
	struct dm_instance_node *ret;

	if (kw->type != T_OBJECT)
		return NULL;

	if (!dm_get_element_ref(basesel, &baseref))
		return NULL;

	if (!base->instance)
		if (!dm_alloc_instance(kw, base)) {
			debug("(): alloc_instance failed\n");
			return NULL;
		}

	if (dm_instance_node_count(base) >= kw->u.t.max)
		return NULL;

	debug("(): id %hx, mask: %hx\n", id, id & DM_ID_MASK);

	if (!(id & DM_ID_MASK)) {
		struct dm_instance_node *elem;
		DM_VALUE instance;

		id++;
		set_DM_INT(instance, id);
		elem = find_instance(base, 0, T_INSTANCE, &instance);
		while (elem) {
			id++;
			elem = dm_instance_next(base, elem);
			if (!elem || elem->instance > id)
				break;
		}
	}

	ret = dm_alloc_instance_node(kw->u.t.table, basesel, id);
	if (!ret)
		return NULL;

	debug("(): added table %hx for token %p\n", id, kw->u.t.table);
	insert_instance(base, ret);

	if ((kw->flags & F_ADD) && kw->fkts.instance.add)
		kw->fkts.instance.add(kw->u.t.table, ret->instance, base, ret);

	notify(-1, basesel, id, *baseref.st_value, NOTIFY_ADD);

	return ret;
}

dm_id dm_get_element_id_by_name(const char *name, size_t l, const struct dm_table *kw)
{
	int i;

	if (!kw)
		return DM_ERR;

	for (i = 0; i < kw->size; i++) {
		if (kw->table[i].key && strlen(kw->table[i].key) == l && strncmp(kw->table[i].key, name, l) == 0)
			return i + 1;
	}
	return DM_ERR;
}

DM_VALUE *dm_get_instance_node_ref_by_id(struct dm_instance *base, dm_id id)
{
	dm_assert(base);

	DM_VALUE instance = init_DM_INT(id, 0);
	struct dm_instance_node *n;

	n = find_instance(base, 0, T_INSTANCE, &instance);
	if (n)
		return &n->table;

	return NULL;
}

struct dm_instance_node *dm_get_instance_node_by_id(struct dm_instance *base, dm_id id)
{
	dm_assert(base);

	DM_VALUE instance = init_DM_INT(id, 0);

	return find_instance(base, 0, T_INSTANCE, &instance);
}

/*
static struct dm_value_table *get_instance_by_id(dm_id id, struct dm_instance *base)
{
	struct dm_instance_node elem = { .instance = id };

	return RB_FIND(dm_instance, &base, &elem);
}
*/

int dm_get_element_ref(const dm_selector sel, struct dm_element_ref *ref)

{
	int i;
	int r = 0;

	const struct dm_table *kw_base = &dm_root;
	struct dm_value_table *st_base  = dm_value_store;

	memset(ref, 0, sizeof(struct dm_element_ref));
	ref->st_type = T_TOKEN;

	debug("(): start: kw_base: %p, size: %d, st_base: %p\n", kw_base, kw_base->size, st_base);

	for (i = 0; kw_base && st_base; i++) {

		dm_id id = sel[i];
		if (!id)
			return r;

		r = 1;
		ref->id = id;
		ref->kw_base = kw_base;
		ref->st_base = st_base;

		debug("(): %d, %d\n", id, ref->st_type);

		if (ref->st_type == T_OBJECT) {
			ref->st_type = T_INSTANCE;
			ref->st_value = dm_get_instance_node_ref_by_id(DM_INSTANCE(*ref->st_value), id);
			if (!ref->st_value)
				return 0;
			DM_parity_assert(*ref->st_value);
			st_base = DM_TABLE(*ref->st_value);
		} else {
			/* current kw element */
			ref->kw_elem = kw_base->table + id - 1;
			ref->st_value = ref->st_base->values + id - 1;
			DM_parity_assert(*ref->st_value);

			if (ref->kw_elem->type == T_TOKEN || ref->kw_elem->type == T_OBJECT) {
				if (ref->st_type == T_TOKEN || ref->st_type == T_INSTANCE) {
					/* current data type */
					ref->st_type = ref->kw_elem->type;

					/* new base values */
					kw_base = ref->kw_elem->u.t.table;
					if (ref->st_type != T_OBJECT)
						st_base = DM_TABLE(*ref->st_value);
					else
						/*
						 * FIXME: not wrong,
						 * but could/should be
						 * cleaner
						 */
						st_base = (struct dm_value_table *)DM_INSTANCE(*ref->st_value);
				} else
					debug("(): error\n");
			} else
				return 1;
		}

		debug("(): i: %d, kw: %p, st %p\n", id, kw_base, st_base);
	}

	return 0;
}

static int dm_get_element_type_from_ref(const struct dm_element_ref *ref)
{
	if (!ref || !ref->kw_elem)
		return 0;

	if (ref->kw_elem->type == T_COUNTER)
		return T_UINT;

	return ref->kw_elem->type;
}

static const struct dm_element *dm_get_element_from_ref(const struct dm_element_ref *ref)
{
	if (!ref || !ref->kw_elem)
		return NULL;

	return ref->kw_elem;
}

DM_VALUE dm_get_element_value(int type, const struct dm_element_ref *ref)
{
	DM_VALUE value = init_DM_UINT(0, 0);
	DM_parity_update(value);

	if (!ref || !ref->kw_elem || !ref->st_value)
		return value;

	DM_parity_assert(*ref->st_value);
	if (ref->kw_elem->type == T_COUNTER) {
		if (type == T_ANY || type == T_INT || type == T_UINT)
			return *ref->st_value;
	} else
		if (ref->kw_elem->flags & F_GET) {
			return ref->kw_elem->fkts.value.get(ref->st_base, ref->id, ref->kw_elem, *ref->st_value);
		} else if (type == T_ANY || ref->kw_elem->type == type)
			return *ref->st_value;

	return value;
}

DM_RESULT dm_set_string_value(DM_VALUE *st, const char *s)
{
	DM_parity_assert(*st);
	dm_free_string_value(st);
	if (s && *s) {
		set_DM_STRING(*st, strdup(s));
		DM_parity_update(*st);
		if (!DM_STRING(*st))
			return DM_OOM;
		DM_MEM_ADD(strlen(DM_STRING(*st)));
	} else {
		set_DM_STRING(*st, NULL);
		DM_parity_update(*st);
	}
	return DM_OK;
}

DM_RESULT dm_set_binary_value(DM_VALUE *st, const binary_t *t)
{
	DM_parity_assert(*st);
	dm_free_binary_value(st);
	if (t && t->len) {
		binary_t *n;

		n = malloc(sizeof(binary_t) + t->len);
		if (!n)
			return DM_OOM;
		memcpy(n, t, sizeof(binary_t) + t->len);
		set_DM_BINARY(*st, n);
		DM_MEM_ADD(sizeof(binary_t) + n->len);
	} else
		set_DM_BINARY(*st, NULL);

	DM_parity_update(*st);
	return DM_OK;
}

DM_RESULT dm_set_binary_data(DM_VALUE *st, unsigned int len, const uint8_t *data)
{
	DM_parity_assert(*st);
	dm_free_binary_value(st);
	if (len && data) {
		binary_t *n;

		n = malloc(sizeof(binary_t) + len);
		if (!n)
			return DM_OOM;
		n->len = len;
		memcpy(n->data, data, len);
		set_DM_BINARY(*st, n);
		DM_MEM_ADD(sizeof(binary_t) + n->len);
	} else
		set_DM_BINARY(*st, NULL);

	DM_parity_update(*st);
	return DM_OK;
}

DM_RESULT dm_set_selector_value(DM_VALUE *st, const dm_selector s)
{
	dm_assert(st != 0);
	DM_type_assert(*st, T_SELECTOR);
	DM_parity_assert(*st);

	if (!s || !s[0])
		dm_free_selector_value(st);
	else {
		if (!DM_SELECTOR(*st)) {
			set_DM_SELECTOR(*st, malloc(sizeof(dm_selector)));
			if (!DM_SELECTOR(*st))
				return DM_OOM;
			DM_MEM_ADD(sizeof(dm_selector));
		}
		/* selectors are fixed length, so we can simply overwrite them */
		dm_selcpy(*DM_SELECTOR(*st), s);
	}

	DM_parity_update(*st);
	return DM_OK;
}

static void value_update_action(const struct dm_element_ref *ref, int slot)
{
	ref->st_value->flags |= DV_UPDATED;
	DM_parity_update(*ref->st_value);
	if (ref->kw_elem->flags & F_INDEX)
		update_index(ref->id, cast_table2node(ref->st_base));
	notify(slot, ref->st_base->id, ref->id, *ref->st_value, NOTIFY_CHANGE);
	action(ref->kw_elem->action, ref->st_base->id, ref->id, DM_CHANGE);
}

static DM_RESULT dm_set_value(int type, const struct dm_element_ref *ref, const DM_VALUE val)
{
	DM_RESULT r = DM_OK;

	if (!ref || !ref->kw_elem || !ref->st_value)
		return DM_VALUE_NOT_FOUND;

	if (ref->kw_elem->type == type) {
		DM_parity_assert(*ref->st_value);
		if (ref->kw_elem->flags & F_SET) {
			r = ref->kw_elem->fkts.value.set(ref->st_base, ref->id, ref->kw_elem, ref->st_value, val);
			DM_parity_update(*ref->st_value);
		} else if (ref->kw_elem->type == T_STR) {
			r = dm_set_string_value(ref->st_value, DM_STRING(val));
		} else if (ref->kw_elem->type == T_BINARY || ref->kw_elem->type == T_BASE64) {
			r = dm_set_binary_value(ref->st_value, DM_BINARY(val));
		} else if (ref->kw_elem->type == T_SELECTOR) {
			if (!DM_SELECTOR(val)) {
				dm_free_selector_value(ref->st_value);
				r = DM_OK;
			} else
				r = dm_set_selector_value(ref->st_value, *DM_SELECTOR(val));
		} else {
			memcpy(&ref->st_value->_v, &val._v, sizeof(val._v));
			DM_parity_update(*ref->st_value);
		}

		if (r == DM_OK && (val.flags & DV_UPDATED))
			value_update_action(ref, -1);

		return r;
	}
	return DM_INVALID_TYPE;
}

DM_RESULT dm_set_any_value_by_selector(const dm_selector sel, int type, const DM_VALUE val)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref))
		return dm_set_value(type, &ref, val);

	return DM_VALUE_NOT_FOUND;
}

static DM_RESULT dm_overwrite_value(int type, const struct dm_element_ref *ref, DM_VALUE val, int slot)
{
	DM_RESULT r = DM_OK;

	if (!ref || !ref->kw_elem || !ref->st_value)
		return DM_VALUE_NOT_FOUND;

	if (ref->kw_elem->type == type) {
		DM_parity_assert(*ref->st_value);
		if (ref->kw_elem->flags & F_SET) {
			r = ref->kw_elem->fkts.value.set(ref->st_base, ref->id, ref->kw_elem, ref->st_value, val);
			if(r == DM_OK)
				dm_free_any_value(ref->kw_elem, &val);
		} else
			memcpy(&ref->st_value->_v, &val._v, sizeof(val._v));

		DM_parity_update(*ref->st_value);

		if (r == DM_OK && (val.flags & DV_UPDATED))
			value_update_action(ref, slot);

		return r;
	}
	return DM_INVALID_TYPE;
}

DM_RESULT dm_overwrite_any_value_by_selector(const dm_selector sel, int type, DM_VALUE val, int slot)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref))
		return dm_overwrite_value(type, &ref, val, slot);

	return DM_VALUE_NOT_FOUND;
}

int dm_mark_updated_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref)) {
		DM_parity_assert(*ref.st_value);
		ref.st_value->flags |= DV_UPDATED;
		DM_parity_update(*ref.st_value);
	}
	return 0;
}

DM_VALUE dm_get_any_value_by_selector(const dm_selector sel, int type)
{
	struct dm_element_ref ref;
	DM_VALUE ret;

	memset(&ret, 0, sizeof(ret));
	if (dm_get_element_ref(sel, &ref))
		ret = dm_get_element_value(type, &ref);

	return ret;
}

struct dm_instance *dm_get_instance_ref_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref) &&
	    ref.kw_elem->type == T_OBJECT &&
	    ref.st_type == T_OBJECT)
			return (DM_INSTANCE(*ref.st_value));

	return NULL;
}

struct dm_instance_node *dm_get_instance_node_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref) &&
	    ref.kw_elem->type == T_OBJECT &&
	    ref.st_type == T_INSTANCE) {
		/* WARNING: major pointer magic
		 * dm_get_instance_node_ref_by_id() return a pointer to the table element,
		 * re-cast to the node itself
		 */
		struct dm_instance_node *node = cast_node_table_ref2node(ref.st_value);
		assert_struct_magic(node, NODE_MAGIC);
		return node;
	}

	return NULL;
}
/*
 *
 */

int dm_get_value_by_selector(const dm_selector sel, int type, void *value)
{
	struct dm_element_ref ref;

	if (!value)
		return 0;

	if (dm_get_element_ref(sel, &ref)) {
		DM_VALUE val = dm_get_element_value(type, &ref);

		switch (type) {
			case T_ENUM:
			case T_INT:
				*(int *)value = DM_INT(val);
				break;
			case T_UINT:
				*(uint *)value = DM_UINT(val);
				break;
			case T_INT64:
				*(int64_t *)value = DM_INT64(val);
				break;
			case T_UINT64:
				*(uint64_t *)value = DM_UINT64(val);
				break;
			case T_STR:
				*(char **)value = DM_STRING(val);
				break;
			case T_BINARY:
			case T_BASE64:
				*(binary_t **)value = DM_BINARY(val);
				break;
			case T_SELECTOR:
				*(dm_selector **)value = DM_SELECTOR(val);
				break;
			case T_BOOL:
				*(char *)value = DM_BOOL(val);
				break;
			default:
				return 0;
		}
		return 1;
	}
	return 0;
}

DM_RESULT dm_get_value_by_selector_cb(const dm_selector sel, int type, void *userData,
					 DM_RESULT (*cb)(void *, const dm_selector, const struct dm_element *, int st_type, const DM_VALUE))
{
	struct dm_element_ref ref;

	if (!cb)
		return DM_INVALID_VALUE;

	if (dm_get_element_ref(sel, &ref)) {
		DM_VALUE val = dm_get_element_value(type, &ref);
		return cb(userData, sel, dm_get_element_from_ref(&ref), ref.st_type, val);
	}
	return DM_VALUE_NOT_FOUND;
}

DM_RESULT dm_set_value_by_selector(const dm_selector sel, int type, const void *value)
{
	if (value) {
		DM_VALUE val;

		switch (type) {
		case T_ENUM:
		case T_UINT:
			set_DM_UINT(val, *(uint *)value);
			break;

		case T_INT:
			set_DM_INT(val, *(int *)value);
			break;

		case T_UINT64:
			set_DM_UINT64(val, *(uint64_t *)value);
			break;

		case T_INT64:
			set_DM_INT64(val, *(int64_t *)value);
			break;

		case T_BOOL:
			set_DM_BOOL(val, *(char *)value);
			break;

		case T_STR:
			set_DM_STRING(val, (char *)value);
			break;

		case T_BINARY:
		case T_BASE64:
			set_DM_BINARY(val, (binary_t *)value);
			break;

		case T_DATE:
			set_DM_TIME(val, *(time_t *)value);
			break;

		case T_TICKS:
			set_DM_TICKS(val, *(ticks_t *)value);
			break;

		case T_SELECTOR:
			set_DM_SELECTOR(val, (dm_selector *)value);
			break;

		case T_IPADDR4:
		case T_IPADDR6:
		case T_COUNTER:
		default:
			return DM_INVALID_TYPE;

		}
		val.flags = DV_UPDATED;
		return dm_set_any_value_by_selector(sel, type, val);
	}
	return DM_INVALID_VALUE;
}

DM_RESULT dm_set_value_by_selector_cb(const dm_selector sel, void *value,
					 void *userData, DM_RESULT (*cb)(void *,
									 const dm_selector,
									 const struct dm_element *,
									 const void *,
									 DM_VALUE *))
{
	struct dm_element_ref ref;
	DM_RESULT r;

	if (!value)
		return DM_INVALID_VALUE;

	if (dm_get_element_ref(sel, &ref)) {
		DM_VALUE val;

		memset(&val, 0, sizeof(val));
		r = cb(userData, sel, dm_get_element_from_ref(&ref), value, &val);
		if (r != DM_OK)
			return r;

		return dm_set_value(dm_get_element_type_from_ref(&ref), &ref, val);
	}

	return DM_VALUE_NOT_FOUND;
}

DM_RESULT dm_get_value_ref_by_selector_cb(const dm_selector sel, void *value,
					     void *userData, DM_RESULT (*cb)(void *,
									     const dm_selector,
									     const struct dm_element *,
									     struct dm_value_table *,
									     const void *,
									     DM_VALUE *))
{
	struct dm_element_ref ref;
	DM_RESULT r = DM_VALUE_NOT_FOUND;

	if (!value)
		return DM_INVALID_VALUE;

	if (dm_get_element_ref(sel, &ref))
		r = cb(userData, sel, dm_get_element_from_ref(&ref), ref.st_base, value, ref.st_value);

	return r;
}


struct dm_instance_node *dm_add_instance_by_selector(const dm_selector sel, dm_id *id)
{
	struct dm_element_ref ref;
	struct dm_instance_node *node = NULL;

	if (!id)
		return NULL;

	if (dm_get_element_ref(sel, &ref) &&
	    ref.st_type == T_OBJECT) {
		debug("(): %p, %p, %d, %p, %d, %p\n", ref.kw_base, ref.st_base, ref.kw_elem->type, ref.st_value, ref.st_type, DM_INSTANCE(*ref.st_value));
		node = dm_add_instance(ref.kw_elem, DM_INSTANCE(*ref.st_value), sel, *id);
		if (node) {
			node->table.flags |= DV_UPDATED;
			DM_parity_update(node->table);
			ref.st_value->flags |= DV_UPDATED;
			DM_parity_update(*ref.st_value);
			(*id) = node->instance;
			return node;
		}
	}

	return NULL;
}

int dm_add_table_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref) &&
	    ref.kw_elem->type == T_TOKEN &&
	    !DM_TABLE(*ref.st_value)) {
		set_DM_TABLE(*ref.st_value, dm_alloc_table(ref.kw_elem->u.t.table, sel, 0));
		DM_parity_update(*ref.st_value);

		debug("(): adding table for token with %d elements: %p\n",
		      ref.kw_elem->u.t.table->size, DM_TABLE(*ref.st_value));
		return 1;
	}
	return 0;
}

static void dm_del_table(const struct dm_table *kw, struct dm_value_table *st);

static void dm_del_instance(const struct dm_element *e,
			       struct dm_instance *base,
			       struct dm_instance_node *node)
{
	const struct dm_table *kw = e->u.t.table;

	DM_parity_assert(node->table);

	remove_instance(base, node);

	if ((e->flags & F_DEL) && e->fkts.instance.del)
		e->fkts.instance.del(kw, node->instance, base, node);

	node->table.flags |= DV_DELETED;
	DM_parity_update(node->table);
	notify_sel(-1, DM_TABLE(node->table)->id, node->table, NOTIFY_DEL);
	action_sel(e->action, DM_TABLE(node->table)->id, DM_DEL);

	dm_del_table(kw, DM_TABLE(node->table));
	dm_free_instance_node(kw, node);

}

static void dm_del_object(const struct dm_element *e, struct dm_instance *base)
{
	struct dm_instance_node *node;

	ENTER();
	debug("(): e: %p, base: %p\n", e, base);

	while ((node = dm_instance_root(base)))
		dm_del_instance(e, base, node);

	EXIT();
}

static void dm_del_element(const struct dm_element *e, DM_VALUE *v)
{
	ENTER();

	debug("(): e: %p, v: %p\n", e, v);
	debug("(): e: %s\n", e->key);

	DM_parity_assert(*v);
	switch (e->type) {
		case T_TOKEN:
			if (DM_TABLE(*v)) {
				dm_del_table(e->u.t.table, DM_TABLE(*v));
				dm_free_table(e->u.t.table, DM_TABLE(*v));
			}
			break;
		case T_OBJECT:
			dm_del_object(e, DM_INSTANCE(*v));
			dm_free_instance(DM_INSTANCE(*v));
			break;
		case T_STR:
			dm_free_string_value(v);
			break;
		case T_BINARY:
		case T_BASE64:
			dm_free_binary_value(v);
			break;
		case T_SELECTOR:
			dm_free_selector_value(v);
			break;
		default:
			break;
	}
	DM_parity_invalidate(*v);
	EXIT();
}

static void dm_del_table(const struct dm_table *kw, struct dm_value_table *st)
{
	int i;

	ENTER();
	/*
	 * we delete in reverse order - this assumes that counters always
	 * precede instances, we have to remove the instances *before* we
	 * kill the counter, otherwise the reference from the instance to
	 * the counter will be invalid when we try to decrement the counter
	 */
	for (i = kw->size - 1; i >= 0; i--) {
		dm_del_element(&kw->table[i], &st->values[i]);
		action(kw->table[i].action, st->id, i + 1, DM_DEL);
	}

	EXIT();
}

static void dm_del_object_instance(struct dm_element_ref *ref)
{
	ENTER();

	if (!ref || !ref->kw_elem || !ref->st_value) {
		EXIT();
		return;
	}

	/*
	 * WARNING: major pointer magic ahead depending on the exact
	 * structure layout, be extra carefull!!!
	 *
	 * dm_get_instance_node_ref_by_id() return a pointer to the table element,
	 * re-cast to the node itself
	 */

	struct dm_instance *inst = (struct dm_instance *)ref->st_base;
	struct dm_instance_node *node = cast_node_table_ref2node(ref->st_value);

	assert_struct_magic(node, NODE_MAGIC);

	dm_del_instance(ref->kw_elem, inst, node);

	EXIT();
}

int dm_del_object_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref) &&
	    ref.st_type == T_INSTANCE) {
		debug("(): %p, %p, %p, %p\n", ref.kw_base, ref.st_base, ref.kw_elem, ref.st_value);
		debug("(): %d, %s, %d, %d\n", ref.id, ref.kw_elem->key, ref.kw_elem->type, ref.st_type);

		dm_del_object_instance(&ref);
		return 1;
	}
	return 0;
}

int dm_del_table_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref)) {
		debug("(): %p, %p, %p, %p\n", ref.kw_base, ref.st_base, ref.kw_elem, ref.st_value);
		debug("(): %d, %s, %d, %d\n", ref.id, ref.kw_elem->key, ref.kw_elem->type, ref.st_type);

		if (ref.st_type == T_INSTANCE) {
			dm_del_object_instance(&ref);
		} else if (ref.st_type == T_OBJECT) {
			/* don't kill the instance element itself,
			 * otherwise the counter reference will be invalid */
			dm_del_object(ref.kw_elem, DM_INSTANCE(*ref.st_value));
			action(ref.kw_elem->action, ref.st_base->id, ref.id, DM_DEL);
		} else {
			dm_del_element(ref.kw_elem, ref.st_value);
			action(ref.kw_elem->action, ref.st_base->id, ref.id, DM_DEL);
		}
		return 1;
	}
	return 0;
}

static int dm_walk_element_cb(int level, void *userData,
			      walk_cb *cb,
			      const struct dm_element_ref *ref)
{
	int ret = 1;
	DM_VALUE value;
	value = dm_get_element_value(T_ANY, ref);

	switch(ref->kw_elem->type) {
		case T_TOKEN:
			if (DM_TABLE(value)) {
				if (cb(userData, CB_table_start, ref->id, ref->kw_elem, value)) {
					if (level - 1)
						ret &= dm_walk_table_cb(level - 1, userData, cb, ref->kw_elem->u.t.table, DM_TABLE(value));
					cb(userData, CB_table_end, ref->id, ref->kw_elem, value);
				}
			}
			break;
		case T_OBJECT:
			ret &= dm_walk_object_cb(level, userData, cb, ref->id, ref->kw_elem, value);
			break;
		default:
			cb(userData, CB_element, ref->id, ref->kw_elem, value);
			break;
	}
	return ret;
}

int dm_walk_table_cb(int level, void *userData, walk_cb *cb,
		     const struct dm_table *kw_base,
		     struct dm_value_table *st_base)
{
	int ret = 1;
	struct dm_element_ref ref;

	debug("(%p, %p)\n", kw_base, st_base);

	ref.kw_base = kw_base;
	ref.kw_elem = kw_base->table;
	ref.st_base = st_base;
	ref.st_value = st_base->values;

	debug("(): size: %d, %s\n", kw_base->size, kw_base->name);

	for (ref.id = 1; ref.id <= kw_base->size; ref.id++, ref.kw_elem++, ref.st_value++)
		ret &= dm_walk_element_cb(level, userData, cb, &ref);

	return ret;
}

int dm_walk_object_cb(int level, void *userData, walk_cb *cb, dm_id id,
		      const struct dm_element *kw_elem,
		      DM_VALUE value)
{
	int ret = 1;
	debug("(element: %p, instance: %p)\n", kw_elem, DM_INSTANCE(value));

	if (!kw_elem)
		return 0;

	if (cb(userData, CB_object_start, id, kw_elem, value)) {
		struct dm_instance_node *node;

		if (level - 1) {
			for (node = dm_instance_first(DM_INSTANCE(value));
			     node != NULL;
			     node = dm_instance_next(DM_INSTANCE(value), node)) {
				debug(": %s - %d - %d\n",  kw_elem->key, node->instance, node->idm);
				if (cb(userData, CB_object_instance_start, node->instance, kw_elem, node->table)) {
					if (level - 2)
						ret &= dm_walk_table_cb(level - 2, userData, cb, kw_elem->u.t.table, DM_TABLE(node->table));
					cb(userData, CB_object_instance_end, node->instance, kw_elem, node->table);
				}
			}
		}
		cb(userData, CB_object_end, id, kw_elem, value);
	}

	return ret;
}

static int dm_walk_instance_cb(int level, void *userData,
				  walk_cb *cb, dm_id id,
				  const struct dm_element *kw_elem,
				  DM_VALUE value)
{
	int ret = 1;

	if (cb(userData, CB_object_instance_start, id, kw_elem, value)) {
		if (level - 1)
			ret &= dm_walk_table_cb(level - 1, userData, cb, kw_elem->u.t.table, DM_TABLE(value));
		cb(userData, CB_object_instance_end, id, kw_elem, value);
	}

	return ret;
}

int dm_walk_by_selector_cb(const dm_selector sel, int level, void *userData, walk_cb *cb)
{
	struct dm_element_ref ref;
	int ret = 1;

	ENTER();

	if (!cb)
		return 0;

	if (dm_get_element_ref(sel, &ref)) {
		// struct dm_value_table *st = DM_TABLE(ref.st->values[ref.st_index]);

		//debug("(): 1: %p, 2: %p, v: %p\n", &dm_root, &keyword_2_tab, dm_value_store);
		//debug("(%s): %d, %d, %d\n", name,
		//ref.kw->table[ref.kw_index].type, ref.kw_index,
		//ref.st_type);
#if DEBUG
		debug("(): %s\n", ref.kw_base->name);
#endif
		debug("(): kw elem: %p, type: %d, ref idx: %p, type %d\n", ref.kw_elem, ref.kw_elem->type, ref.st_value, ref.st_type);

		if (ref.kw_elem->type == T_OBJECT) {
			if (ref.st_type == T_INSTANCE)
				ret &= dm_walk_instance_cb(level, userData, cb, ref.id, ref.kw_elem, *ref.st_value);
			else
				ret &= dm_walk_object_cb(level, userData, cb, ref.id, ref.kw_elem, *ref.st_value);
		} else
			ret &= dm_walk_element_cb(level, userData, cb, &ref);
	}

	return ret;
}

const struct dm_table *dm_get_object_table_by_selector(const dm_selector sel)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref) &&
	    ref.kw_elem->type == T_OBJECT)
		return ref.kw_elem->u.t.table;

	return NULL;
}

static int update_flags_table(const struct dm_table *kw, struct dm_value_table *st);
static int update_flags_object(const struct dm_element *elem, struct dm_instance *base);

static int update_flags_element(const struct dm_table *kw, struct dm_value_table *st, int index)
{
	int ret;

	const struct dm_element *elem;

	if (!kw->table)
		return 0;

	elem = &kw->table[index];
	ret = st->values[index].flags & (DV_UPDATED | DV_NOTIFY);

	switch(elem->type) {
		case T_TOKEN:
			if (DM_TABLE(st->values[index]))
				ret |= update_flags_table(elem->u.t.table, DM_TABLE(st->values[index]));
			break;

		case T_OBJECT:
			ret |= update_flags_object(elem, DM_INSTANCE(st->values[index]));
			break;

		default:
			break;
	}

	if (ret) {
		debug("(): updated, %s - %s\n", kw->name, elem->key);
		st->values[index].flags |= ret;
		DM_parity_update(st->values[index]);
	}

	return ret;
}

static int update_flags_table(const struct dm_table *kw, struct dm_value_table *st)
{
	int ret = 0;

	debug("(%p, %p)\n", kw, st);

	if (!kw || !st)
		return 0;

	debug("(): size: %d, %s\n", kw->size, kw->name);

	for (int i = 0; i < kw->size; i++)
		ret |= update_flags_element(kw, st, i);

	debug("(): res: %d\n", ret);
	return ret;
}

static int update_flags_object(const struct dm_element *elem, struct dm_instance *base)
{
	struct dm_instance_node *node;
	int ret = 0;

	if (!elem || !base)
		return 0;

	debug("(): base: %p, elem: %s\n", base, elem->key);

	for (node = dm_instance_first(base);
	     node != NULL;
	     node = dm_instance_next(base, node)) {
		int r = update_flags_table(elem->u.t.table, DM_TABLE(node->table));
		if (r) {
			node->table.flags |= r;
			DM_parity_update(node->table);
		}
		ret |= node->table.flags;
	}

	debug("(): res: %d\n", ret);
	return ret;
}

void dm_update_flags(void)
{
	update_flags_table(&dm_root, dm_value_store);
	debug("(): res: %d\n", dm_value_store->values[0].flags);
}

int dm_selcmp(const dm_selector s1, const dm_selector s2, size_t len)
{
	if (s1 && s2) {
		for (size_t i = 0; i < len; i++) {
			if (unlikely(s1[i] == 0 && s2[i] == 0))
				break;
			if (s1[i] < s2[i])
				return -1;
			else if (s1[i] > s2[i])
				return 1;
		}
		return 0;
	} else if (s1)
		return 1;
	else
		return -1;
}

int dm_binarycmp(binary_t * const a, binary_t * const b)
{
	if (a && b) {
		int r;

		r = memcmp(a->data, b->data,
			   a->len > b->len ? b->len : a->len);
		if (r != 0)
			return r;
		if (a->len > b->len)
			return 1;
		else if (a->len > b->len)
			return -1;
		else
			return 0;
	} else if (!a && b)
		return -1;
	else if (a && !b)
		return 1;
	else
		return 0;
}

int dm_compare_values(int type, DM_VALUE *a, DM_VALUE *b)
{
	switch (type) {
	case T_INSTANCE:
		if (DM_NODE(*a)->instance > DM_NODE(*b)->instance)
			return 1;
		else if (DM_NODE(*a)->instance < DM_NODE(*b)->instance)
			return -1;
		else
			return 0;

	case T_UINT:
		if (DM_UINT(*a) > DM_UINT(*b))
			return 1;
		else if (DM_UINT(*a) < DM_UINT(*b))
			return -1;
		else
			return 0;

	case T_INT:
		if (DM_INT(*a) > DM_INT(*b))
			return 1;
		else if (DM_INT(*a) < DM_INT(*b))
			return -1;
		else
			return 0;

	case T_UINT64:
		if (DM_UINT64(*a) > DM_UINT64(*b))
			return 1;
		else if (DM_UINT64(*a) < DM_UINT64(*b))
			return -1;
		else
			return 0;

	case T_INT64:
		if (DM_INT64(*a) > DM_INT64(*b))
			return 1;
		else if (DM_INT64(*a) < DM_INT64(*b))
			return -1;
		else
			return 0;

	case T_BOOL:
		return DM_BOOL(*a) == DM_BOOL(*b) ? 0 : 1;

	case T_STR:
		if (DM_STRING(*a) && DM_STRING(*b))
			return strcmp(DM_STRING(*a), DM_STRING(*b));
		else if (!DM_STRING(*a) && DM_STRING(*b))
			return -1;
		else if (DM_STRING(*a) && !DM_STRING(*b))
			return 1;
		else
			return 0;

	case T_BINARY:
	case T_BASE64:
		return dm_binarycmp(DM_BINARY(*a), DM_BINARY(*b));

	case T_DATE:
		if (DM_TIME(*a) > DM_TIME(*b))
			return 1;
		else if (DM_TIME(*a) < DM_TIME(*b))
			return -1;
		else
			return 0;

	case T_TICKS:
		if (DM_TICKS(*a) > DM_TICKS(*b))
			return 1;
		else if (DM_TICKS(*a) < DM_TICKS(*b))
			return -1;
		else
			return 0;

	case T_ENUM:
		if (DM_ENUM(*a) > DM_ENUM(*b))
			return 1;
		else if (DM_ENUM(*a) - DM_ENUM(*b))
			return -1;
		else
			return 0;

	case T_SELECTOR:
		if (DM_SELECTOR(*a) && DM_SELECTOR(*b))
			return dm_selcmp(*DM_SELECTOR(*a), *DM_SELECTOR(*b), DM_SELECTOR_LEN);
		else if (!DM_SELECTOR(*a) && DM_SELECTOR(*b))
			return -1;
		else if (DM_SELECTOR(*a) && !DM_SELECTOR(*b))
			return 1;
		else
			return 0;

	case T_IPADDR4:
		return memcmp(DM_IP4_REF(*a), DM_IP4_REF(*b), sizeof(struct in_addr));

	case T_IPADDR6:
		return memcmp(DM_IP6_REF(*a), DM_IP6_REF(*b), sizeof(struct in6_addr));

	default:
		/* last resort, use pointer address */
		return a - b;
	}
}

/*
 * set methods
 */

void dm_set_bool_by_id(struct dm_value_table *ift, dm_id id, char bool)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_BOOL(ift->values[id - 1], bool);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_string_by_id(struct dm_value_table *ift, dm_id id, const char *val)
{
	DM_parity_assert(ift->values[id - 1]);
	dm_set_string_value(&ift->values[id - 1], val);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_binary_by_id(struct dm_value_table *ift, dm_id id, const binary_t *val)
{
	DM_parity_assert(ift->values[id - 1]);
	dm_set_binary_value(&ift->values[id - 1], val);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_binary_data_by_id(struct dm_value_table *ift, dm_id id, unsigned int len, const uint8_t *data)
{
	DM_parity_assert(ift->values[id - 1]);
	dm_set_binary_data(&ift->values[id - 1], len, data);
	__DM_NOTIFY_BY_ID(ift, id);
}

int dm_set_binary_data_by_selector(const dm_selector sel, unsigned int len, uint8_t * const data, int flags)
{
	struct dm_element_ref ref;

	if (dm_get_element_ref(sel, &ref) && ref.kw_elem && ref.st_value) {
		int r;

		if (ref.kw_elem->type != T_BINARY && ref.kw_elem->type != T_BASE64)
			return DM_INVALID_TYPE;

		r = dm_set_binary_data(ref.st_value, len, data);

		if (r == DM_OK && (flags & DV_UPDATED))
			value_update_action(&ref, -1);

		return r;
	}

	return DM_VALUE_NOT_FOUND;
}

void dm_set_enum_by_id(struct dm_value_table *ift, dm_id id, int val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_ENUM(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_counter_by_id(struct dm_value_table *ift, dm_id id, unsigned int val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_int_by_id(struct dm_value_table *ift, dm_id id, int val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_INT(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_uint_by_id(struct dm_value_table *ift, dm_id id, unsigned int val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_int64_by_id(struct dm_value_table *ift, dm_id id, int64_t val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_INT64(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_uint64_by_id(struct dm_value_table *ift, dm_id id, uint64_t val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_UINT64(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_time_by_id(struct dm_value_table *ift, dm_id id, time_t t)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_TIME(ift->values[id - 1], t);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_ticks_by_id(struct dm_value_table *ift, dm_id id, ticks_t val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_TICKS(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_selector_by_id(struct dm_value_table *ift, dm_id id, const dm_selector sel)
{
	DM_parity_assert(ift->values[id - 1]);
	dm_set_selector_value(&ift->values[id - 1], sel);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_ipv4_by_id(struct dm_value_table *ift, dm_id id, struct in_addr val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_IP4(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}

void dm_set_ipv6_by_id(struct dm_value_table *ift, dm_id id, struct in6_addr val)
{
	DM_parity_assert(ift->values[id - 1]);
	set_DM_IP6(ift->values[id - 1], val);
	DM_parity_update(ift->values[id - 1]);
	__DM_NOTIFY_BY_ID(ift, id);
}
