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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include <sys/tree.h>

#define SDEBUG
#include "debug.h"

#include "tr069_token.h"
#include "tr069_action.h"

#if defined(SDEBUG)

#define type_map_init(x)   [x] = #x

#include "tr069_action_debug.c"

const char *t_types[] = {
	type_map_init(DM_ADD),
	type_map_init(DM_CHANGE),
	type_map_init(DM_DEL),
};

#endif

struct exec_node {
	RB_ENTRY (exec_node) node;

	enum dm_actions action;
	tr069_selector sel;
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

	r = tr069_selcmp(a->sel, b->sel, TR069_SELECTOR_LEN);
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

static void insert_action(enum dm_actions action, const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const struct tr069_action *act = dm_actions[action];
	struct exec_node *node;
	struct exec_node *res;

	node = talloc_zero(exec_chain, struct exec_node);
	if (!node)
		return;

	node->action = action;
	node->type = type;
	tr069_selcpy(node->sel, sel);
	if (act->sel_len >= 0)
		node->sel[act->sel_len] = 0;

	debug(": action: %s, selector: %s, type: %s", t_actions[action], sel2str(b1, node->sel), t_types[type]);

	res = RB_INSERT(action_tree, exec_chain, node);
	if (res != NULL) {
		debug(": duplicate insert");
		talloc_free(node);
	}

}

void action_sel(enum dm_actions action, const tr069_selector sel, enum dm_action_type type)
{
	if (action == DM_NONE)
		return;

	if (!exec_chain)
		exec_chain = talloc_zero(NULL, struct action_tree);
	if (!exec_chain)
		return;

	insert_action(action, sel, type);

	const struct tr069_action *act = dm_actions[action];
	for (int i = 0; i < act->chain_cnt; i++)
		insert_action(act->chain[i], sel, type);
}

void action(enum dm_actions action, const tr069_selector sel, tr069_id id, enum dm_action_type type)
{
	tr069_selector s;

	if (action == DM_NONE)
		return;

	tr069_selcpy(s, sel);
	tr069_selcat(s, id);

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

	RB_FOREACH(node, action_tree, exec_chain)
		if (dm_actions[node->action]->action)
			dm_actions[node->action]->action(node->sel, node->type);

	debug(": post");

	RB_FOREACH(node, action_tree, exec_chain)
		if (dm_actions[node->action]->post)
			dm_actions[node->action]->post(node->sel, node->type);

	clear_actions();
	EXIT();
}

void clear_actions(void)
{
	talloc_free(exec_chain);
	exec_chain = NULL;
}
