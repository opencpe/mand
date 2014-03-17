/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef   	DM_INDEX_H_
# define   	DM_INDEX_H_

#include "dm_token.h"
#include "dm_store.h"

struct dm_instance_node *dm_instance_root(struct dm_instance *);

struct dm_instance_node *dm_instance_first(struct dm_instance *);
struct dm_instance_node *dm_instance_last(struct dm_instance *);
struct dm_instance_node *dm_instance_next(struct dm_instance *, struct dm_instance_node *);
struct dm_instance_node *dm_instance_prev(struct dm_instance *, struct dm_instance_node *);

struct dm_instance_node *dm_instance_first_idx(struct dm_instance *, dm_id);
struct dm_instance_node *dm_instance_last_idx(struct dm_instance *, dm_id);
struct dm_instance_node *dm_instance_next_idx(struct dm_instance *, dm_id, struct dm_instance_node *);
struct dm_instance_node *dm_instance_prev_idx(struct dm_instance *, dm_id, struct dm_instance_node *);

dm_id dm_idm2id(struct dm_instance *, int);

unsigned int dm_instance_node_count(struct dm_instance *);

void insert_instance(struct dm_instance *, struct dm_instance_node *);
void remove_instance(struct dm_instance *, struct dm_instance_node *);

void update_index(dm_id, struct dm_instance_node *);
void update_instance_node_index(struct dm_instance_node *);
struct dm_instance_node *find_instance(struct dm_instance *, dm_id, int, DM_VALUE *);

struct dm_instance_tree *dm_alloc_instance(const struct dm_element *, struct dm_instance *);
void dm_free_instance(struct dm_instance *);
void dm_instance_set_counter(struct dm_instance *, struct dm_value_table *, dm_id);
struct dm_instance_node *dm_alloc_instance_node(const struct dm_table *, const dm_selector, dm_id);
void dm_free_instance_node(const struct dm_table *, struct dm_instance_node *);

static inline struct dm_instance_node *
find_instance_by_selector(const dm_selector sel, dm_id id, int type, DM_VALUE *val)
{
	struct dm_instance *inst = dm_get_instance_ref_by_selector(sel);

	return inst ? find_instance(inst, id, type, val) : NULL;
}

#endif 	    /* !DM_INDEX_H_ */
