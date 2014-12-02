/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <ralloc.h>

#include <sys/tree.h>

#define SDEBUG
#include "debug.h"

#include "dm_token.h"
#include "dm_action.h"
#include "dm_dmconfig.h"

#if defined(SDEBUG)

#define type_map_init(x)   [x] = #x

#include "dm_action_debug.c"

const char *t_types[] = {
	type_map_init(DM_ADD),
	type_map_init(DM_CHANGE),
	type_map_init(DM_DEL),
};

#endif

struct exec_node {
	RB_ENTRY (exec_node) node;

	enum dm_actions action;
	dm_selector sel;
	enum dm_action_type type;
};

RB_HEAD(action_tree, exec_node) *exec_chain = NULL;

static int cmp_action(struct exec_node *a, struct exec_node *b)
{
	int r;

	if (a->action < b->action)
		return -1;
	else if (a->action > b->action)
		return 1;

	r = dm_selcmp(a->sel, b->sel, DM_SELECTOR_LEN);
	if (r == 0) {
		if (a->type < b->type)
			return -1;
		else if (a->type > b->type)
			return 1;
	}

	return r;
}

RB_PROTOTYPE(action_tree, exec_node, node, cmp_action);
RB_GENERATE(action_tree, exec_node, node, cmp_action);

static void insert_action(enum dm_actions action, const dm_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const struct dm_action *act = dm_actions[action];
	struct exec_node *node;
	struct exec_node *res;

	node = rzalloc(exec_chain, struct exec_node);
	if (!node)
		return;

	node->action = action;
	node->type = type;
	dm_selcpy(node->sel, sel);
	if (act->sel_len >= 0)
		node->sel[act->sel_len] = 0;

	debug(": action: %s, selector: %s, type: %s", t_actions[action], sel2str(b1, node->sel), t_types[type]);

	res = RB_INSERT(action_tree, exec_chain, node);
	if (res != NULL) {
		debug(": duplicate insert");
		ralloc_free(node);
	}

}

void action_sel(enum dm_actions action, const dm_selector sel, enum dm_action_type type)
{
	if (action == DM_NONE)
		return;

	if (!exec_chain)
		exec_chain = rzalloc(NULL, struct action_tree);
	if (!exec_chain)
		return;

	insert_action(action, sel, type);

	const struct dm_action *act = dm_actions[action];
	for (int i = 0; i < act->chain_cnt; i++)
		insert_action(act->chain[i], sel, type);
}

void action(enum dm_actions action, const dm_selector sel, dm_id id, enum dm_action_type type)
{
	dm_selector s;

	if (action == DM_NONE)
		return;

	dm_selcpy(s, sel);
	dm_selcat(s, id);

	action_sel(action, s, type);
}

void exec_actions_pre(void)
{
	struct exec_node *node;

	ENTER();

	if (!exec_chain) {
		EXIT();
		return;
	}

	debug(": pre");

	/* possibly need to run this reverse .... */
	RB_FOREACH(node, action_tree, exec_chain)
		if (dm_actions[node->action]->pre)
			dm_actions[node->action]->pre(node->sel, node->type);

	EXIT();
}

void exec_actions(void)
{
	struct exec_node *node;

	ENTER();

	if (!exec_chain) {
		EXIT();
		return;
	}

	debug(": action");

	RB_FOREACH(node, action_tree, exec_chain) {
		if (dm_actions[node->action]->action)
			dm_actions[node->action]->action(node->sel, node->type);
		dm_event_broadcast(node->sel, node->type);
	}

	debug(": post");

	RB_FOREACH(node, action_tree, exec_chain)
		if (dm_actions[node->action]->post)
			dm_actions[node->action]->post(node->sel, node->type);

	clear_actions();
	EXIT();
}

void clear_actions(void)
{
	ralloc_free(exec_chain);
	exec_chain = NULL;
}
