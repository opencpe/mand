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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/tree.h>

#define SDEBUG
#include "debug.h"

#include "compiler.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_store_priv.h"
#include "tr069_index.h"
#include "tr069_notify.h"
#include "tr069_action.h"
#include "tr069_cache.h"

struct cache cache;

static int
cache_compare(struct cache_item *a, struct cache_item *b)
{
        return tr069_selcmp(a->sb, b->sb, TR069_SELECTOR_LEN);
}

RB_GENERATE(cache, cache_item, node, cache_compare);

void cache_free()
{
	struct cache_item *item;

	while ((item = RB_ROOT(&cache))) {
		RB_REMOVE(cache, &cache, item);

		tr069_free_any_value(item->elem, &item->new_value);
		free(item);
	}
}

void cache_reset()
{
	struct cache_item *item;

	while ((item = RB_ROOT(&cache))) {
		RB_REMOVE(cache, &cache, item);

		tr069_free_any_value(item->elem, &item->new_value);
		item->old_value->flags &= ~DV_UPDATE_PENDING;
		DM_parity_update(*item->old_value);
		free(item);
	}
}

void cache_add(const tr069_selector sb, const char *name,
	       const struct tr069_element *elem,
	       struct tr069_value_table *base,
	       DM_VALUE *old_value, DM_VALUE new_value,
	       unsigned int code, char *msg)
{
	tr069_id id = 1;
	struct cache_item si, *item;

	if (!name)
		return;

	tr069_selcpy(si.sb, sb);

	item = RB_FIND(cache, &cache, &si);
	if (!item) {
		item = malloc(sizeof(struct cache_item));
		if (!item)
			return;

		for (int i = 0; i < TR069_SELECTOR_LEN; i++) {
			if (sb[i] == 0)
				break;
			id = sb[i];
		}

		item->id = id;
		tr069_selcpy(item->sb, sb);
		item->name = name;
		item->elem = elem;
		item->base = base;
		item->old_value = old_value;
		item->new_value = new_value;
		item->code = code;
		item->msg = msg;

		RB_INSERT(cache, &cache, item);
	} else {
		item->new_value = new_value;
		item->code = code;
		item->msg = msg;
	}
	DM_parity_update(item->new_value);
}

int cache_validate()
{
	int r = 1;
	struct cache_item *item;

	RB_FOREACH(item, cache, &cache) {
		if (item->elem &&
		    item->code == 0 &&
		    item->elem->fkts.value.validate)
			r &= item->elem->fkts.value.validate(item->base, item->id, item->elem, item->new_value, &item->code, &item->msg);
	}
	return r;
}

void cache_apply(int slot)
{
	struct cache_item *item;

	while ((item = RB_ROOT(&cache))) {
		RB_REMOVE(cache, &cache, item);

		if (item->elem->flags & F_SET) {
			item->elem->fkts.value.set(item->base, item->id, item->elem, item->old_value, item->new_value);

			tr069_free_any_value(item->elem, &item->new_value);
		} else
			memcpy(&item->old_value->_v,  &item->new_value._v, sizeof(item->new_value._v));

		item->old_value->flags &= ~DV_UPDATE_PENDING;
		item->old_value->flags |= DV_UPDATED;
		DM_parity_update(*item->old_value);

		if (item->elem->flags & F_INDEX)
			update_index(item->id, cast_table2node(item->base));

		notify_sel(slot, item->sb, *item->old_value, NOTIFY_CHANGE);
		action_sel(item->elem->action, item->sb, DM_CHANGE);

		free(item);
	}
}

DM_VALUE tr069_cache_get_any_value_by_id(const struct tr069_value_table *ift, tr069_id id)
{
	DM_VALUE val = { _init_DM_type(T_ANY) };

	if (!ift)
		return val;

	if (unlikely((ift->values[id - 1].flags & DV_UPDATE_PENDING) == DV_UPDATE_PENDING)) {
		struct cache_item item, *i;

		tr069_selcpy(item.sb, ift->id);
		tr069_selcat(item.sb, id);

		i = RB_FIND(cache, &cache, &item);
		if (!i)
			return val;

		return i->new_value;
	} else
		return ift->values[id - 1];
}

DM_VALUE tr069_cache_get_any_value_by_selector(const tr069_selector sel, int type)
{
	struct tr069_element_ref ref;
	DM_VALUE val = { _init_DM_type(T_ANY) };

	if (tr069_get_element_ref(sel, &ref)) {

		if (ref.kw_elem->type == T_INSTANCE || ref.kw_elem->type == T_OBJECT)
			return val;

		if (ref.st_value &&
		    unlikely((ref.st_value->flags & DV_UPDATE_PENDING) == DV_UPDATE_PENDING))
		{
			struct cache_item item, *i;

			tr069_selcpy(item.sb, sel);

			i = RB_FIND(cache, &cache, &item);
			if (!i)
				return val;

			DM_parity_assert(i->new_value);
			return i->new_value;
		}
		return tr069_get_element_value(type, &ref);
	}

	return val;
}

DM_RESULT tr069_cache_get_value_by_selector_cb(const tr069_selector sel, int type, void *userData,
					 DM_RESULT (*cb)(void *, const tr069_selector, const struct tr069_element *, const DM_VALUE))
{
	struct tr069_element_ref ref;

	if (!cb)
		return DM_INVALID_VALUE;

	if (tr069_get_element_ref(sel, &ref)) {

		if (ref.kw_elem->type == T_INSTANCE || ref.kw_elem->type == T_OBJECT)
			return DM_INVALID_TYPE;

		if (type != T_ANY && ref.kw_elem->type != type)
			return DM_INVALID_TYPE;

		if (unlikely((ref.st_value->flags & DV_UPDATE_PENDING) == DV_UPDATE_PENDING))
		{
			struct cache_item item, *i;

			tr069_selcpy(item.sb, sel);

			i = RB_FIND(cache, &cache, &item);
			if (!i)
				return DM_VALUE_NOT_FOUND;

			DM_parity_assert(i->new_value);
			return cb(userData, sel, ref.kw_elem, i->new_value);
		}

		DM_VALUE val = tr069_get_element_value(type, &ref);
		return cb(userData, sel, ref.kw_elem, val);
	}
	return DM_VALUE_NOT_FOUND;
}
