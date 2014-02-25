/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm_cfgversion.h"

static int version = 0;

int
dm_get_cfg_version(void)
{
	return version;
}

void
dm_set_cfg_version(int v)
{
	version = v;
}


