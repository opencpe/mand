#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "routers.h"

const char *routes_models[] = {
#if defined(WITH_BRCM43XX)
	[ROUTER_WRT54G]             = "Linksys WRT54G/GS",
	[ROUTER_WRT54G1X]           = "Linksys WRT54G 1.x",
	[ROUTER_LINKSYS_WRT55AG]    = "Linksys WRT55AG v1",
	[ROUTER_ASUS_550G_DELUXE]   = "Asus WL500G-Deluxe",
	[ROUTER_BUFFALO_WBR54G]     = "Buffalo WBR-G54 / WLA-G54",
	[ROUTER_BUFFALO_WBR2G54S]   = "Buffalo WBR2-G54 / WBR2-G54S",
	[ROUTER_BUFFALO_WLA2G54L]   = "Buffalo WLA2-G54L",
	[ROUTER_BUFFALO_WHRG54S]    = "Buffalo WHR-G54S",
	[ROUTER_BUFFALO_HP_WHRG54S] = "Buffalo WHR-HP-G54",
	[ROUTER_BUFFALO_WZRRSG54]   = "Buffalo WZR-RS-G54",
	[ROUTER_BUFFALO_WLAG54G]    = "Buffalo WLA-G54C",
	[ROUTER_MOTOROLA_V1]        = "Motorola WR850G v1",
	[ROUTER_MOTOROLA]           = "Motorola WR850G",
	[ROUTER_SIEMENS_505_V1]     = "Siemens SE505 v1",
	[ROUTER_SIEMENS_505_V2]     = "Siemens SE505 v2",
	[ROUTER_BELKIN_F5D7130]     = "Belkin F5D7130 / F5D7330",
	[ROUTER_BELKIN_F5D7230_V1]  = "Belkin F5D7230-4 v1000",
	[ROUTER_BELKIN_F5D7230_V2]  = "Belkin F5D7230-4 v1444",
	[ROUTER_ASUS_500G_PREMIUM]  = "ASUS WL500g.Premium",
#endif
	[ROUTER_WRAP]               = "PC-Engines WRAP",
};

#if !defined(WITH_BRCM43XX)

int getRouterBrand ()
{
	return ROUTER_WRAP;
}

#endif
