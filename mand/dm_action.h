/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_ACTION_H
#define __DM_ACTION_H

enum dm_action_type {
	DM_ADD,
	DM_CHANGE,
	DM_DEL,
};

typedef void action_fkt(const dm_selector, enum dm_action_type);

struct dm_action {
	short sel_len;

	action_fkt *pre;				/* function to execute during the pre phase */
	action_fkt *action;				/* function to execute during the action phase */
	action_fkt *post;				/* function to execute during the post phase */

	int chain_cnt;
	enum dm_actions chain[];			/* also execute these actions */
};

void action(enum dm_actions, const dm_selector, dm_id, enum dm_action_type)  __attribute__((nonnull (2)));
void action_sel(enum dm_actions, const dm_selector, enum dm_action_type)  __attribute__((nonnull (2)));

void exec_actions_pre(void);
void exec_actions(void);
void clear_actions(void);

extern const struct dm_action *dm_actions[];

#endif
