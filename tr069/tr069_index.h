/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 Andreas Schultz <as@travelping.com>
 *
 */

#ifndef   	TR069_INDEX_H_
# define   	TR069_INDEX_H_

#include "tr069_token.h"
#include "tr069_store.h"

struct tr069_instance_node *tr069_instance_root(struct tr069_instance *);

struct tr069_instance_node *tr069_instance_first(struct tr069_instance *);
struct tr069_instance_node *tr069_instance_last(struct tr069_instance *);
struct tr069_instance_node *tr069_instance_next(struct tr069_instance *, struct tr069_instance_node *);
struct tr069_instance_node *tr069_instance_prev(struct tr069_instance *, struct tr069_instance_node *);

struct tr069_instance_node *tr069_instance_first_idx(struct tr069_instance *, tr069_id);
struct tr069_instance_node *tr069_instance_last_idx(struct tr069_instance *, tr069_id);
struct tr069_instance_node *tr069_instance_next_idx(struct tr069_instance *, tr069_id, struct tr069_instance_node *);
struct tr069_instance_node *tr069_instance_prev_idx(struct tr069_instance *, tr069_id, struct tr069_instance_node *);

tr069_id tr069_idm2id(struct tr069_instance *, int);

unsigned int tr069_instance_node_count(struct tr069_instance *);

void insert_instance(struct tr069_instance *, struct tr069_instance_node *);
void remove_instance(struct tr069_instance *, struct tr069_instance_node *);

void update_index(tr069_id, struct tr069_instance_node *);
void update_instance_node_index(struct tr069_instance_node *);
struct tr069_instance_node *find_instance(struct tr069_instance *, tr069_id, int, DM_VALUE *);

struct tr069_instance_tree *tr069_alloc_instance(const struct tr069_element *, struct tr069_instance *);
void tr069_free_instance(struct tr069_instance *);
void tr069_instance_set_counter(struct tr069_instance *, struct tr069_value_table *, tr069_id);
struct tr069_instance_node *tr069_alloc_instance_node(const struct tr069_table *, const tr069_selector, tr069_id);
void tr069_free_instance_node(const struct tr069_table *, struct tr069_instance_node *);

static inline struct tr069_instance_node *
find_instance_by_selector(tr069_selector sel, tr069_id id, int type, DM_VALUE *val)
{
	struct tr069_instance *inst = tr069_get_instance_ref_by_selector(sel);

	return inst ? find_instance(inst, id, type, val) : NULL;
}

#endif 	    /* !TR069_INDEX_H_ */
