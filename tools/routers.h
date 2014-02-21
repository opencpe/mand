#ifndef __ROUTERS_H
#define __ROUTERS_H

enum {
	// Linksys WRT54G, WRT54GS and WRT54GL all models except WRT54G v1.0, v1.1
	ROUTER_WRT54G = 1,

	// Linksys WRT54G v1.0 and v1.1 (4702 cpu)
	ROUTER_WRT54G1X,

	// Linksys WRT55AG v1 (4702 cpu)
	ROUTER_LINKSYS_WRT55AG,

	// Asus WL-550G-Deluxe
	ROUTER_ASUS_550G_DELUXE,

	// Buffalo WBR-G54, WLA-G54 and WLA-G54C (4702 cpu)
	ROUTER_BUFFALO_WBR54G,

	// Buffalo WBR2-G54, WBR2-G54S and Buffalo WLA2-G54L
	ROUTER_BUFFALO_WBR2G54S,
	ROUTER_BUFFALO_WLA2G54L,       //should work like a WBR2

	// Buffalo WHR-G54S and WHR-HP-G54
	ROUTER_BUFFALO_WHRG54S,
	ROUTER_BUFFALO_HP_WHRG54S,     //no differences between these models. so we leave it

	// Buffalo WZR-RS-G54 (4704 cpu)
	ROUTER_BUFFALO_WZRRSG54,

	// Buffalo WLA-G54C
	ROUTER_BUFFALO_WLAG54G,

	// Motorola WR850G v1 (4702 cpu)
	ROUTER_MOTOROLA_V1,

	// Motorola WR850G v2
	ROUTER_MOTOROLA,

	// RT480W generic and branded (fccid: Askey H8N-RT480W), (4712 cpu + ADM6996)
	// Siemens se505 v2
	ROUTER_SIEMENS_505_V1,
	ROUTER_SIEMENS_505_V2,

	// Microtik RouterBOARD 500
	ROUTER_BOARD_500,

	// Belkin F5D7130 / F5D7330
	ROUTER_BELKIN_F5D7130,

	// Belkin F5D7230-4 v1000
	ROUTER_BELKIN_F5D7230_V1,

	// Belkin F5D7230-4 v1444 (4712 cpu, 2MB flash) (fccid: Belkin K7S-F5D72304)
	ROUTER_BELKIN_F5D7230_V2,

	// PC Engines WRAP Board
	ROUTER_WRAP,

	// Asus WL-500gP
	ROUTER_ASUS_500G_PREMIUM,
};

extern const char *routes_models[];

int getRouterBrand(void);

#endif
