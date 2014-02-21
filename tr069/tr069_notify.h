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

#ifndef __TR069_NOTIFY_H
#define __TR069_NOTIFY_H

#include <sys/tree.h>

#include "tr069_token.h"

enum notify_type {
	NOTIFY_ADD,
	NOTIFY_CHANGE,
	NOTIFY_DEL
};

struct notify_item {
	RB_ENTRY (notify_item) node;

	int level;
	tr069_selector sb;

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

DM_RESULT set_notify_single_slot_element(const struct tr069_element *elem, DM_VALUE *value, int slot, uint32_t ntfy);
DM_RESULT tr069_set_notify_by_selector(const tr069_selector sel, int slot, int value) __attribute__((nonnull (1)));
DM_RESULT tr069_set_notify_by_selector_recursive(const tr069_selector sel, int slot, int value) __attribute__((nonnull (1)));

static inline
uint32_t notify_default(const struct tr069_element *elem)
{
	if (elem->flags & F_ACS_NTFY)
		return ACTIVE_NOTIFY;

	return 0;
};

void notify(int slot, const tr069_selector sel, tr069_id id,
	    const DM_VALUE value, enum notify_type type) __attribute__((nonnull (2)));
void notify_sel(int slot, const tr069_selector sel,
		const DM_VALUE value, enum notify_type type) __attribute__((nonnull (2)));

void exec_pending_notifications(void);

struct notify_queue *get_notify_queue(int slot);
void clear_notify_queue(struct notify_queue *queue);

void tr069_notify_init(EV_P);

#endif
