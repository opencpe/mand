/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <ev.h>

#include <sys/tree.h>

#include "dm_token.h"
#include "dm_store.h"
#include "dm_store_priv.h"
#include "dm_index.h"
#include "dm_notify.h"
#include "dm_dmconfig.h"

//#define SDEBUG
#include "debug.h"

static int notify_pending = 0;

static int
notify_compare(struct notify_item *a, struct notify_item *b)
{
        return dm_selcmp(a->sb, b->sb, DM_SELECTOR_LEN);
}

RB_GENERATE(notify_queue, notify_item, node, notify_compare);

static void dm_notify(void *data, struct notify_queue *queue);

static uint16_t slot_map = 0x0001;
static int slot_cnt = 1;
static struct slot slots[16] = { { .cb = dm_notify }, };

static int notify_is_valid(const struct dm_element *elem, int ntfy)
{
	if (elem->flags & F_ACS_NTFY && ntfy != ACTIVE_NOTIFY)
		return 0;

	if (elem->flags & F_ACS_NO_NTFY && ntfy >= ACTIVE_NOTIFY)
		return 0;

	return 1;
}

static void reset_notify_table(const struct dm_table *kw, struct dm_value_table *st, uint32_t mask);
static void reset_notify_object(const struct dm_element *elem, struct dm_instance *base, uint32_t mask);

static void reset_notify_element(const struct dm_table *kw, struct dm_value_table *st, int index, uint32_t mask)
{
	const struct dm_element *elem;

	if (!kw->table)
		return;

	elem = &kw->table[index];

	switch(elem->type) {
		case T_TOKEN:
			if (DM_TABLE(st->values[index]))
				reset_notify_table(elem->u.t.table, DM_TABLE(st->values[index]), mask);
			break;

		case T_OBJECT:
			reset_notify_object(elem, DM_INSTANCE(st->values[index]), mask);
			break;

		default:
			break;
	}

	st->values[index].notify &= mask;
	DM_parity_update(st->values[index]);
}

static void reset_notify_table(const struct dm_table *kw, struct dm_value_table *st, uint32_t mask)
{
	debug("(%p, %p)\n", kw, st);

	if (!kw || !st)
		return;

	debug("(): size: %d, %s\n", kw->size, kw->name);

	for (int i = 0; i < kw->size; i++)
		reset_notify_element(kw, st, i, mask);
}

static void reset_notify_object(const struct dm_element *elem, struct dm_instance *base, uint32_t mask)
{
	struct dm_instance_node *node;

	if (!elem || !base)
		return;

	debug("(): base: %p, elem: %s\n", base, elem->key);

	for (node = dm_instance_first(base);
	     node != NULL;
	     node = dm_instance_next(base, node))
		reset_notify_table(elem->u.t.table, DM_TABLE(node->table), mask);
}

static void dm_reset_notify_slot(int slot)
{
	uint32_t mask = ~(3 << (slot * 2));

	reset_notify_table(&dm_root, dm_value_store, mask);
}

int alloc_slot(notify_cb *cb, void *data)
{
	int slot;

	if (slot_cnt >= 16)
		return -1;

	slot = ffs(~slot_map) - 1;
	slot_map |= 1 << slot;
	slot_cnt++;
	slots[slot].data = data;
	slots[slot].cb = cb;

	return slot;
}

void free_slot(int slot)
{
	if (slot < 1 || slot > 15)
		/* invalid slot number */
		return;

	if (!(slot_map & (1 << slot)))
		/* slot has already been released */
		return;

	clear_notify_queue(get_notify_queue(slot));

	slot_map &= ~(1 << slot);
	slot_cnt--;
	memset(&slots[slot], 0, sizeof(struct slot));

	dm_reset_notify_slot(slot);
}

void notify(int slot, const dm_selector sel, dm_id id,
	    const DM_VALUE value, enum notify_type type)
{
	uint32_t ntfy = value.notify;
	dm_selector nsl;

	if (ntfy == 0)
		/* not notify's at all */
		return;

	dm_selcpy(nsl, sel);
	dm_selcat(nsl, id);

	notify_sel(slot, nsl, value, type);
}

void notify_sel(int slot, const dm_selector sel,
		const DM_VALUE value, enum notify_type type)
{
#if defined(SDEBUG)
        char b1[MAX_PARAM_NAME_LEN];
#endif
	struct notify_item si;

	uint32_t ntfy = value.notify;

	if (ntfy == 0)
		/* not notify's at all */
		return;

	debug("(): %s, %08x ... %d", dm_sel2name(sel, b1, sizeof(b1)), ntfy, slot);

	dm_selcpy(si.sb, sel);

	for (int i = 0; i < 16; i++) {
		/* skip notify for slot */
		if (i != slot) {
			int level = ntfy & 0x0003;
			if (level) {
				struct notify_item *item;
				item = RB_FIND(notify_queue, &slots[i].queue, &si);
				if (!item) {
					item = malloc(sizeof(struct notify_item));
					if (!item)
						continue;
					dm_selcpy(item->sb, sel);

					RB_INSERT(notify_queue, &slots[i].queue, item);
					notify_pending = 1;
				}
				item->level = level;
				item->type = type;
				item->value = value;
			}
		}
		ntfy >>= 2;
	}
}

struct notify_queue *get_notify_queue(int slot)
{
	return &slots[slot].queue;
}

void clear_notify_queue(struct notify_queue *queue)
{
	struct notify_item *item;

	while ((item = RB_ROOT(queue))) {
		RB_REMOVE(notify_queue, queue, item);
		free(item);
	}
}

void exec_pending_notifications(void)
{
	if (!notify_pending)
		return ;

	ENTER();

	for (int i = 0; i < 16; i++) {
		if (slots[i].cb && RB_ROOT(&slots[i].queue))
			slots[i].cb(slots[i].data, &slots[i].queue);
	}
	notify_pending = 0;

	EXIT();
}

DM_RESULT set_notify_single_slot_element(const struct dm_element *elem, DM_VALUE *value, int slot, uint32_t ntfy)
{
	uint32_t mask = ~(0x0003 << (slot * 2));
	uint32_t notify;

	notify = (value->notify & mask) | ((ntfy & 0x0003) << (slot * 2));

	if (slot == 0) {
		if (!notify_is_valid(elem, notify & 0x0003))
			return DM_INVALID_VALUE;

		value->notify = notify;
		if (notify_default(elem) != (value->notify & 0x0003))
			value->flags |= DV_NOTIFY;
		else
			value->flags &= ~DV_NOTIFY;
	} else
		value->notify = notify;
	DM_parity_update(*value);
	return DM_OK;
}

DM_RESULT dm_set_notify_by_selector(const dm_selector sel, int slot, int value)
{
	struct dm_element_ref ref;

	ENTER();

	if (dm_get_element_ref(sel, &ref)) {
#if DEBUG
		debug("(): %s\n", ref.kw_base->name);
#endif
		debug("(): kw elem: %p, type: %d, ref idx: %p, type %d\n", ref.kw_elem, ref.kw_elem->type, ref.st_value, ref.st_type);

		switch (ref.kw_elem->type) {
		case T_TOKEN:
			EXIT();
			return DM_INVALID_TYPE;

		case T_OBJECT:
			if (ref.st_type == T_INSTANCE) {
				struct dm_instance_node *node = cast_node_table_ref2node(ref.st_value);

				EXIT();
				/* set notify on a instance */
				return set_notify_single_slot_element(ref.kw_elem, &node->table, slot, value);
			}
			/* FALL THROUGH */

		default:
			EXIT();
			return set_notify_single_slot_element(ref.kw_elem, ref.st_value, slot, value);
		}
	}

	EXIT();
	return DM_VALUE_NOT_FOUND;
}

static void set_notify_slot_table(const struct dm_table *kw, struct dm_value_table *st, int slot, uint32_t ntfy);
static void set_notify_slot_object(const struct dm_element *elem, struct dm_instance *base, int slot, uint32_t ntfy);

static void set_notify_slot_element(const struct dm_table *kw, struct dm_value_table *st, int index, int slot, uint32_t ntfy)
{
	const struct dm_element *elem;

	if (!kw->table)
		return;

	elem = &kw->table[index];

	switch(elem->type) {
		case T_TOKEN:
			if (DM_TABLE(st->values[index]))
				set_notify_slot_table(elem->u.t.table, DM_TABLE(st->values[index]), slot, ntfy);
			break;

		case T_OBJECT:
			set_notify_slot_object(elem, DM_INSTANCE(st->values[index]), slot, ntfy);
			break;

		default:
			break;
	}

	set_notify_single_slot_element(elem, &st->values[index], slot, ntfy);
}

static void set_notify_slot_table(const struct dm_table *kw, struct dm_value_table *st, int slot, uint32_t ntfy)
{
	debug("(%p, %p)\n", kw, st);

	if (!kw || !st)
		return;

	debug("(): size: %d, %s\n", kw->size, kw->name);

	for (int i = 0; i < kw->size; i++)
		set_notify_slot_element(kw, st, i, slot, ntfy);
}

static void set_notify_slot_object(const struct dm_element *elem, struct dm_instance *base, int slot, uint32_t ntfy)
{
	struct dm_instance_node *node;

	if (!elem || !base)
		return;

	debug("(): base: %p, elem: %s\n", base, elem->key);

	for (node = dm_instance_first(base);
	     node != NULL;
	     node = dm_instance_next(base, node)) {
		/* set notify on a instance */
		set_notify_single_slot_element(elem, &node->table, slot, ntfy);
		set_notify_slot_table(elem->u.t.table, DM_TABLE(node->table), slot, ntfy);
	}
}

DM_RESULT dm_set_notify_by_selector_recursive(const dm_selector sel, int slot, int value)
{
	struct dm_element_ref ref;

	ENTER();

	if (!sel[0]) {
		debug("(): notify on root\n");
		set_notify_slot_table(&dm_root, dm_value_store, slot, value);
		EXIT();
		return DM_OK;
	} else if (dm_get_element_ref(sel, &ref)) {
#if DEBUG
		debug("(): %s\n", ref.kw_base->name);
#endif
		debug("(): kw elem: %p, type: %d, ref idx: %p, type %d\n", ref.kw_elem, ref.kw_elem->type, ref.st_value, ref.st_type);

		switch (ref.kw_elem->type) {
		case T_TOKEN:
			if (DM_TABLE(*ref.st_value))
				set_notify_slot_table(ref.kw_elem->u.t.table, DM_TABLE(*ref.st_value), slot, value);
			break;

		case T_OBJECT:
			if (ref.st_type == T_OBJECT) {
				/* set notify on instance table */
				set_notify_single_slot_element(ref.kw_elem, ref.st_value, slot, value);
				set_notify_slot_object(ref.kw_elem, DM_INSTANCE(*ref.st_value), slot, value);
			} else {
				struct dm_instance_node *node = cast_node_table_ref2node(ref.st_value);

				/* set notify on a instance */
				set_notify_single_slot_element(ref.kw_elem, &node->table, slot, value);
				set_notify_slot_table(ref.kw_elem->u.t.table, DM_TABLE(node->table), slot, value);
			}

			break;

		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
		EXIT();
		return DM_OK;
	}
	EXIT();
	return DM_VALUE_NOT_FOUND;
}

static void dm_notify(void *data __attribute__ ((unused)), struct notify_queue *queue)
{
#if defined(SDEBUG) && !defined(NDEBUG)
	char buf[MAX_PARAM_NAME_LEN];
	struct notify_item *item;

	RB_FOREACH(item, notify_queue, queue) {
		char *s = NULL;

		s = dm_sel2name(item->sb, buf, sizeof(buf));
		debug("() selector: %s, level: %d, type: %d",
		      s ? : "NULL", item->level, item->type);
	}
#endif

	clear_notify_queue(queue);
}

static ev_prepare notify_ev;

static void notify_prepare_cb(EV_P __attribute__ ((unused)), ev_prepare *w __attribute__ ((unused)),
			      int revents __attribute__ ((unused)))
{
        if (!cfg_session_id) {
		debug(": exec_pending_notifications");
                exec_pending_notifications();
	}
}

void dm_notify_init(EV_P)
{
	ev_prepare_init(&notify_ev, notify_prepare_cb);
	ev_prepare_start(EV_A_ &notify_ev);
}
