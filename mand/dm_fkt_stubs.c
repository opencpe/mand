/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define DMGetStub(x) \
	DM_VALUE x(const struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE) __attribute__ ((weak, alias ("dm_get_Stub")))

#define DMSetStub(x) \
	int x(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE *, DM_VALUE) __attribute__ ((weak, alias ("dm_set_Stub")))

static DM_VALUE dm_get_Stub(const struct dm_value_table *base __attribute__ ((unused)),
			    dm_id id __attribute__ ((unused)),
			    const struct dm_element *elem __attribute__ ((unused)),
			    DM_VALUE val __attribute__ ((unused)))
{
	return val;
}

static int dm_set_Stub(struct dm_value_table *base __attribute__ ((unused)),
		       dm_id id __attribute__ ((unused)),
		       const struct dm_element *elem __attribute__ ((unused)),
		       DM_VALUE *val __attribute__ ((unused)),
		       DM_VALUE value __attribute__ ((unused)))
{
	return 0;
}

#define DMInstanceStub(x) \
	void x(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *) __attribute__ ((weak, alias ("dm_instance_Stub")))

static void dm_instance_Stub(const struct dm_table *kw __attribute__ ((unused)),
			     dm_id id __attribute__ ((unused)),
			     struct dm_instance *inst __attribute__ ((unused)),
			     struct dm_instance_node *node __attribute__ ((unused)))
{
	return;
}
