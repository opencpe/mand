/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_NOTIFY_H
#define __DM_NOTIFY_H

#include <sys/tree.h>
#include <ev.h>

#include "dm_token.h"

enum notify_type {
	NOTIFY_ADD,
	NOTIFY_CHANGE,
	NOTIFY_DEL
};

struct notify_item {
	RB_ENTRY (notify_item) node;

	int level;
	dm_selector sb;

	enum notify_type type;
	DM_VALUE value;
};

RB_HEAD(notify_queue, notify_item);

typedef void notify_cb(void *data, struct notify_queue *queue);

struct slot {
	notify_cb *cb;
	void *data;

	struct notify_queue queue;
};

RB_PROTOTYPE(notify_queue, notify_item, node, notify_compare);

int alloc_slot(notify_cb *cb, void *data);
void free_slot(int slot);

DM_RESULT set_notify_single_slot_element(const struct dm_element *elem, DM_VALUE *value, int slot, uint32_t ntfy);
DM_RESULT dm_set_notify_by_selector(const dm_selector sel, int slot, int value) __attribute__((nonnull (1)));
DM_RESULT dm_set_notify_by_selector_recursive(const dm_selector sel, int slot, int value) __attribute__((nonnull (1)));

static inline
uint32_t notify_default(const struct dm_element *elem)
{
	if (elem->flags & F_ACS_NTFY)
		return ACTIVE_NOTIFY;

	return 0;
};

void notify(int slot, const dm_selector sel, dm_id id,
	    const DM_VALUE value, enum notify_type type) __attribute__((nonnull (2)));
void notify_sel(int slot, const dm_selector sel,
		const DM_VALUE value, enum notify_type type) __attribute__((nonnull (2)));

void exec_pending_notifications(void);

struct notify_queue *get_notify_queue(int slot);
void clear_notify_queue(struct notify_queue *queue);

void dm_notify_init(EV_P);

#endif
