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

#ifndef __TR069_STORE_PRIV_H
#define __TR069_STORE_PRIV_H

#include "tr069.h"
#include "p_table.h"
#include "tr069_token.h"

/*
 *
 */
struct tr069_element_ref {
	tr069_id id;

	const struct tr069_table *kw_base;
	const struct tr069_element *kw_elem;

	int st_type;
	struct tr069_value_table *st_base;
	DM_VALUE *st_value;
};

int tr069_get_element_ref(const tr069_selector sel, struct tr069_element_ref *ref) __attribute__ ((warn_unused_result));
DM_VALUE tr069_get_element_value(int type, const struct tr069_element_ref *ref);

struct tr069_instance_node *tr069_add_instance(const struct tr069_element *, struct tr069_instance *, const tr069_selector, tr069_id)
	__attribute__((nonnull (3)));

#endif
