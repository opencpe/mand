#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>

#include "bcmnvram.h"

#include "routers.h"

#define OID_BELKIN_1        0x001150
#define OID_BELKIN_2        0x0030bd

#define OID_SIEMENS_1       0x0001e3
#define OID_SIEMENS_2       0x009096


#define OID_MOTOROLA_1      0x000ce5
#define OID_MOTOROLA_2      0x000c10

#define OID_BUFFALO_1       0x001601

int getRouterBrand (void)
{
	if (nvram_match ("boardnum", "42") &&
	    nvram_match ("boardtype", "bcm94710ap"))
		{
			return ROUTER_BUFFALO_WBR54G;
		}
	
	if (nvram_match ("boardnum", "100") &&        //added by Eko - experimental
	    nvram_match ("boardtype", "bcm94710dev")) //detect WLA-G54C
		{
			return ROUTER_BUFFALO_WLAG54G;     //should work as WBR54G
		}
	
	if (nvram_match ("product_name", "Product_name") &&
	    nvram_match ("boardrev", "0x10") &&
	    nvram_match ("boardtype", "0x0101") && nvram_match ("boardnum", "00"))
		{
			return ROUTER_BUFFALO_WLA2G54L;
		}

	if (nvram_match ("boardtype", "bcm95365r") &&
	    nvram_match ("boardnum", "45"))
		{
			return ROUTER_ASUS_550G_DELUXE;
		}
	
	if (nvram_match ("boardnum", "00") &&
	    nvram_match ("boardtype", "0x0101") && nvram_match ("boardrev", "0x10"))
		{
			return ROUTER_BUFFALO_WBR2G54S;
		}

	if (nvram_match ("boardnum", "00") &&
	    nvram_match ("boardrev", "0x13") &&
	    nvram_match ("boardtype", "0x467") &&
	    nvram_match ("boardflags", "0x2758"))
		{
			return ROUTER_BUFFALO_WHRG54S;
		}
	if (nvram_match ("boardnum", "00") &&
	    nvram_match ("boardrev", "0x13") &&
	    nvram_match ("boardtype", "0x467") &&
	    nvram_match ("boardflags", "0x1758"))
		{
			return ROUTER_BUFFALO_HP_WHRG54S;
		}
	if (nvram_match ("boardnum", "42") &&
	    nvram_match ("boardtype", "0x042f") &&
	    (nvram_match ("product_name", "Product_name") || nvram_match ("product_name", "WZR-RS-G54")))
		{
			return ROUTER_BUFFALO_WZRRSG54;
		}

	if (nvram_match ("productid", "WL500g.Premium")) {
		return ROUTER_ASUS_500G_PREMIUM;
	}
	
	int r;
	uint8_t mac[3];
	uint32_t et0oid = 0;
	uint32_t et1oid = 0;

	r = sscanf(nvram_safe_get("et0macaddr"), "%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2]);
	if (r == 3)
		et0oid = mac[2] << 16 | mac[1] << 8 | mac[0];

	r = sscanf(nvram_safe_get("et1macaddr"), "%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2]);
	if (r == 3)
		et1oid = mac[2] << 16 | mac[1] << 8 | mac[0];


	if (et0oid != 0 && et1oid != 0)
		{
			if (nvram_match ("clkfreq", "125") &&
			    nvram_match ("boardnum", "100") &&
			    nvram_match ("boardtype", "bcm94710r4"))
				{
					if (et0oid == OID_BELKIN_1)
						{
							return ROUTER_BELKIN_F5D7130;
						}
					if (et0oid == OID_BELKIN_2)
						{
							return ROUTER_BELKIN_F5D7230_V1;
						}
					if ((et0oid == OID_SIEMENS_1 && et1oid == OID_SIEMENS_1) ||
					    (et0oid == OID_SIEMENS_2 && et1oid == OID_SIEMENS_2))
						{
							return ROUTER_SIEMENS_505_V1;
						}
				}
			
			if (nvram_match ("boardtype", "0x0101"))
                                {
					if (et0oid == OID_BELKIN_1 && et1oid == OID_BELKIN_1)
						{
							return ROUTER_BELKIN_F5D7230_V2;
						}

					if ((et0oid == OID_SIEMENS_1 && et1oid == OID_SIEMENS_1) ||
					    (et0oid == OID_SIEMENS_2 && et1oid == OID_SIEMENS_2))
						{
							return ROUTER_SIEMENS_505_V1;
						}
                                }
			
			if (nvram_match ("boardnum", "2") &&
			    nvram_match ("clkfreq", "125") &&
			    nvram_match ("boardtype", "bcm94710dev"))
				{
					if (nvram_match ("GemtekPmonVer", "9") &&
					    ((et0oid == OID_MOTOROLA_1 && et1oid == OID_MOTOROLA_1) ||
					     (et0oid == OID_MOTOROLA_2 && et1oid == OID_MOTOROLA_2)))
						{
							return ROUTER_MOTOROLA_V1;
						}
					else
						{
							return ROUTER_LINKSYS_WRT55AG;
						}
				}
			
		}
	
	if (nvram_match ("boardnum", "42") &&
	    nvram_match ("boardtype", "bcm94710dev"))
		{
			return ROUTER_WRT54G1X;
		}
	if (nvram_invmatch ("CFEver", ""))
		{
			char *cfe = nvram_safe_get ("CFEver");
			if (!strncmp (cfe, "MotoWR", 6))
				{
					return ROUTER_MOTOROLA;
				}
		}
	
	return ROUTER_WRT54G;
}
