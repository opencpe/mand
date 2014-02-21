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

#include <stdlib.h>
#include <string.h>

#include "board_support.h"
#include "process.h"
#include "routers.h"
#ifdef HAVE_LIBNVRAM
#include "nvram.h"
#endif

//#define SDEBUG
#include "debug.h"

static const unsigned char vlan_map[]     = { 5, 0, 1, 2, 3, 4 };
static const unsigned char vlan_map_rev[] = { 5, 4, 3, 2, 1, 0 };

const unsigned char *get_switch_mapping(void)
{
        int router = getRouterBrand();
	switch (router) {
	case ROUTER_BUFFALO_WHRG54S:
	case ROUTER_BUFFALO_HP_WHRG54S:
	case ROUTER_ASUS_500G_PREMIUM:
		return vlan_map;
		break;

	default:
#ifdef HAVE_LIBNVRAM
		{
			long int btype = 0;
			char *bt = nvram_get("boardtype");
			if (bt)
				btype = strtol(bt, NULL, 16);
			if (btype == 0x0467 || btype == 0x042f ||
			    strcmp(bt, "wgt634u") == 0) {
				debug("(): using reverse vlan mapping\n");
				return vlan_map_rev;
			} else
				debug("(): using normal vlan mapping\n");
		}
#endif
		break;
	}
	return vlan_map;
}

void load_switch_driver(void)
{
	insmod("switch-core");
	insmod("switch-adm");
	insmod("switch-robo");
}
