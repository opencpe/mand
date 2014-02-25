/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_STORE_PRIV_H
#define __DM_STORE_PRIV_H

#include "dm.h"
#include "p_table.h"
#include "dm_token.h"

/*
 *
 */
struct dm_element_ref {
	dm_id id;

	const struct dm_table *kw_base;
	const struct dm_element *kw_elem;

	int st_type;
	struct dm_value_table *st_base;
	DM_VALUE *st_value;
};

int dm_get_element_ref(const dm_selector sel, struct dm_element_ref *ref) __attribute__ ((warn_unused_result));
DM_VALUE dm_get_element_value(int type, const struct dm_element_ref *ref);

struct dm_instance_node *dm_add_instance(const struct dm_element *, struct dm_instance *, const dm_selector, dm_id)
	__attribute__((nonnull (3)));

#endif
