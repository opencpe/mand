/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __TR069_ACTION_H
#define __TR069_ACTION_H

enum dm_action_type {
	DM_ADD,
	DM_CHANGE,
	DM_DEL,
};

typedef void action_fkt(const tr069_selector, enum dm_action_type);

struct tr069_action {
	short sel_len;

	action_fkt *pre;				/* function to execute during the pre phase */
	action_fkt *action;				/* function to execute during the action phase */
	action_fkt *post;				/* function to execute during the post phase */

	int chain_cnt;
	enum dm_actions chain[];			/* also execute these actions */
};

void action(enum dm_actions, const tr069_selector, tr069_id, enum dm_action_type)  __attribute__((nonnull (2)));
void action_sel(enum dm_actions, const tr069_selector, enum dm_action_type)  __attribute__((nonnull (2)));

void exec_actions_pre(void);
void exec_actions(void);
void clear_actions(void);

extern const struct tr069_action *dm_actions[];

#endif
