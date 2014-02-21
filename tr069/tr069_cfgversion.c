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

#include "tr069_cfgversion.h"

static int version = 0;

int
tr069_get_cfg_version(void)
{
	return version;
}

void
tr069_set_cfg_version(int v)
{
	version = v;
}


