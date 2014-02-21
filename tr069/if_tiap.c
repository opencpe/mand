#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>

#define SDEBUG 1
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"

#include "ifup.h"

/*#include <wcfglib.h>*/
#include <wcfg_storage.h>
/*#include <wcfg_ioctl.h>*/

#define VAP_MAX 8
#define WIFI_MAX 2

static int setup_ap(const char *device, struct tr069_value_table *ift)
{
	char wifi[20];
	char iface[20];
	struct wcfg_storage_t ldb = wcfg_default;
	const char * ssid;
	unsigned int channel;
	int ret = 0;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	ssid = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID);


	if (ssid && *ssid) {
		strncpy(ldb.essid, ssid, IW_ESSID_MAX_SIZE);
		ldb.essid[IW_ESSID_MAX_SIZE] = '\0';
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Channel */
	channel = tr069_get_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Channel);
	if (channel)
		ldb.d11mode[0].ch = channel;

	ret = wcfg_ioctl_init(&ldb, &auth_none, iface);

	EXIT();
	return ret;
}

static int setup_bridge(const char *device, struct tr069_value_table *ift)
{
	return -1;
}

static int setup_repeater(const char *device, struct tr069_value_table *ift)
{
	return -1;
}

static int setup_sta(const char *device, struct tr069_value_table *ift)
{
	return -1;
}

int tiap_ifup(const char *device, const tr069_selector sel)
{
	char iface[20];
	int opmode;
	struct tr069_value_table *ift;
	const char *iat;
	const char *ipaddr;
	const char *mask;
	int rc;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration */
	if (sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_LANDev_i_WLANConfiguration ||
	    sel[4] == 0) {
		EXIT();
		return -1;
	}

	ift = tr069_get_table_by_selector(sel);
	if (!ift) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Enable */
	if (!tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Enable)) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.DeviceOperationMode */
	opmode = tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_DeviceOperationMode);
	rc = -1;

	switch (opmode) {
		/* InfrastructureAccessPoint */
		case 0:
			rc = setup_ap(device, ift);
			break;

		/* WirelessBridge */
		case 1:
			rc = setup_bridge(device, ift);
			break;

		/* WirelessRepeater */
		case 2:
			rc = setup_repeater(device, ift);
			break;

		/* WirelessStation */
		case 3:
			rc = setup_sta(device, ift);
			break;
	}
	if (rc != 0) {
		EXIT();
		return rc;
	}

#if 0
	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.ClientIsolation */
	int cliso = tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_ClientIsolation);
	vasystem("iwpriv %s ap_bridge %d", iface, cliso ? 0 : 1);
#endif

	EXIT();
	return 0;
}

void tiap_ifdown(int card, int ifc)
{
	char iface[20];
	int i;

	get_tiap_iface(card, ifc, iface, sizeof(iface));

	lan_ipdown(iface);
	lan_ifdown(iface);
}
