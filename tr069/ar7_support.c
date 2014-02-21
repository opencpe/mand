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

#include "board_support.h"
#include "routers.h"
#ifdef HAVE_LIBNVRAM
#include "nvram.h"
#endif

const unsigned char *get_switch_mapping(void)
{
	/** FIXME: tdb */
	return NULL;
}

void load_switch_driver(void)
{
	/** FIXME: tdb */
}
