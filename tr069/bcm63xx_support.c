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
#include "process.h"

static const unsigned char vlan_map_rev[] = { 5, 4, 3, 2, 1, 0 };

const unsigned char *get_switch_mapping(void)
{
	return vlan_map_rev;
}

void load_switch_driver(void)
{
	insmod("switch-core");
	insmod("switch-robo");
}
