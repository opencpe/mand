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

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#ifdef HAVE_NET80211_IEEE80211_IOCTL_H
#define USE_PRIVIOCTL

#include <madwifi/include/compat.h>
#include <madwifi/wireless_copy.h>

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#endif

#define SDEBUG 1
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"

#include "ifup.h"
#include "if_madwifi.h"
#include "lng.h"
#include "process.h"
#include "iso3166.h"

#define HOSTAPD "/usr/sbin/hostapd"
#define HOSTAP_CONF "/var/etc/hostap.%s.conf"
#define WLAN_DEVICE "ath%d"
#define VAP_MAX 8
#define WIFI_MAX 2

#define iwconfig_exec(...) \
	va_invoke_executable("/usr/sbin/iwconfig", ##__VA_ARGS__)

#ifdef USE_PRIVIOCTL

static int
getiw_ioctl(const char *device, int op, struct iwreq *iwr)
{
	int sock, rc;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	strncpy(iwr->ifr_name, device, IFNAMSIZ);

	rc = ioctl(sock, op, iwr);

	close(sock);
	return rc;
}

static int
getiw_priv_ioctl(const char *device, int op, void *data, size_t len)
{
	struct iwreq iwr;
	int sock, rc;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	memset(&iwr, 0, sizeof(struct iwreq));
	strncpy(iwr.ifr_name, device, IFNAMSIZ);

	if (len < IFNAMSIZ) {
		memcpy(iwr.u.name, data, len);
	} else {
		iwr.u.data.pointer = data;
		iwr.u.data.length = len;
	}

	rc = ioctl(sock, op, &iwr);
	close(sock);
	if (rc)
		return -1;

	if (len < IFNAMSIZ)
		memcpy(data, iwr.u.name, len);

	return iwr.u.data.length;
}

static char *
get_possible_channels(const char *device)
{
	char *list = NULL;
	uint8_t channels[32];

	ENTER();

	if (getiw_priv_ioctl(device, IEEE80211_IOCTL_GETCHANLIST,
			     channels, sizeof(channels)) < 0) {
		EXIT();
		return NULL;
	}

	for (unsigned int i = 1; i < sizeof(channels)*8; i++) {
		char chan[4];
		char *new;

		if (!isset(channels, i))
			continue;

		snprintf(chan, sizeof(chan), "%d", i);
		new = tr069_add2list(list, chan);
		free(list);
		list = new;
		if (!list)
			break;
	}

	EXIT_MSG(": channels: %s", list ? : "(NULL)");
	return list;
}

static int
get_txpower(const char *device)
{
	struct iwreq iwr;
	int ret;

	ENTER();

	if (getiw_ioctl(device, SIOCGIWTXPOW, &iwr)) {
		EXIT();
		return -1;
	}

	if (iwr.u.txpower.flags & IW_TXPOW_MWATT)
		ret = iwr.u.txpower.value;
	else
		/* convert dBm to milli Watt */
		ret = (int)floor(pow(10.0, ((double)iwr.u.txpower.value)/10.0));

	EXIT_MSG(": txpower=%d mW", ret);
	return ret;
}

#if 0
static inline int
freq2channel(unsigned int freq)
{
	if (freq == 2484)
		return 14;
	if (freq < 2484)
		return (freq - 2407) / 5;
	if (freq < 5000)
		return 15 + ((freq - 2512) / 20);
	return (freq - 5000) / 5;
}

static int
get_channel(const char *device)
{
	struct iwreq iwr;
	int ret;

	ENTER();

	if (getiw_ioctl(device, SIOCGIWFREQ, &iwr)) {
		EXIT();
		return -1;
	}
	if (iwr.u.freq.m == 0) {
		EXIT();
		return -1;
	}

	if (iwr.u.freq.m <= 1000 && iwr.u.freq.e == 0) {
		/* mantissa is actually a channel number */
		ret = iwr.u.freq.m;
	} else {
		unsigned int freq = iwr.u.freq.m;
		for (int e = iwr.u.freq.e; e; e--)
			freq *= 10;
		freq /= 1000000; /* Hz to MHz */

		ret = freq2channel(freq);
		debug(": m=%d, e=%d, freq=%u (MHz)",
		      iwr.u.freq.m, iwr.u.freq.e, freq);
	}

	EXIT_MSG(": channel=%d", ret);
	return ret;
}
#endif

#else

static inline char *
get_possible_channels(const char *device __attribute__((unused)))
{
	EXIT_MSG(": unsupported");
	return NULL;
}

static inline int
get_txpower(const char *device __attribute__((unused)))
{
	EXIT_MSG(": unsupported");
	return -1;
}

#endif

static inline int get_ath_iface(int card, int ifc, char *iface, int size)
{
	return snprintf(iface, size, WLAN_DEVICE, (card - 1) * VAP_MAX + ifc - 1);
}

static int hostap_pids[VAP_MAX * WIFI_MAX],ap_channel=0;

static int hostap_config(const char *device, struct tr069_value_table *ift)
{
	FILE *fout;
	char fname[256];
	const char *passphrase, *creds;
	int i,rc;

	ENTER();

	snprintf(fname, sizeof(fname), HOSTAP_CONF, device);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Enable */
	if (!tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Enable)) {
		EXIT();
		return 0;
	}

	fout = fopen(fname, "w+");
	if (!fout) {
		EXIT();
		return -1;
	}

	fprintf(fout, "interface=%s\n", device);
/*	fprintf(fout, "bridge=br0\n");*/
	fprintf(fout, "driver=madwifi\n");

	fprintf(fout, "logger_syslog=-1\n");
	fprintf(fout, "logger_syslog_level=2\n");
	fprintf(fout, "logger_stdout=-1\n");
	fprintf(fout, "logger_stdout_level=2\n");
	fprintf(fout, "debug=0\n");
	fprintf(fout, "dump_file=/tmp/hostapd.dump\n");

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	fprintf(fout, "ssid=%s\n", tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID));

	fprintf(fout, "wpa=1\n");
	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAAuthenticationMode */
	if (tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_WPAAuthenticationMode)) {
		/* THIS STUFF HAS NOT BEEN TESTED YET !!! */
		fprintf(fout, "wpa_key_mgmt=WPA-EAP\n");
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.RadiusAuthServer */
		creds = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_HSCfg_RadiusAuthServer);
		if (creds) fprintf(fout, "auth_server_addr=%s\n",creds);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.RadiusAcctServer */
		creds = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_HSCfg_RadiusAcctServer);
		if (creds) fprintf(fout, "acct_server_addr=%s\n",creds);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.RadiusNASIdentifier */
		creds = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_HSCfg_RadiusNASIdentifier);
		if (creds) fprintf(fout, "nas_identifier=%s\n",creds);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.RadiusSecret */
		creds = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_HSCfg_RadiusSecret);
		if (creds) {
			fprintf(fout, "auth_server_shared_secret=%s\n",creds);
			fprintf(fout, "acct_server_shared_secret=%s\n",creds);
		}
	} else {
		fprintf(fout, "wpa_key_mgmt=WPA-PSK\n");

		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAEncryptionModes */
		switch (tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_WPAEncryptionModes)) {
		case cwmp___IGD_LANDev_i_WLANCfg_j_WPAEncryptionModes_TKIPEncryption:
			fprintf(fout, "wpa_pairwise=TKIP\n");
			break;

		case cwmp___IGD_LANDev_i_WLANCfg_j_WPAEncryptionModes_AESEncryption:
			fprintf(fout, "wpa_pairwise=CCMP\n");
			break;

		case cwmp___IGD_LANDev_i_WLANCfg_j_WPAEncryptionModes_TKIPandAESEncryption:
		default:
			fprintf(fout, "wpa_pairwise=TKIP CCMP\n");
			/* the other encryption modes described in TR069 are not supported by hostapd */
		}
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.KeyPassphrase */
	passphrase = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_KeyPassphrase);
	if (passphrase)fprintf(fout, "wpa_passphrase=%s\n",passphrase);
	else {
		fprintf(fout, "wpa_passphrase=mystupiddummypassword\n");
		debug(": Please set a passphrase. Passphrase has ben set to \"mystupiddummypassword\"\n");
	}

	fclose(fout);

	if (sscanf(device, "ath%d", &i)) {
		const char *argv[] = {HOSTAPD, fname, NULL};
		rc = -1;
		if (hostap_pids[i] > 0) {
			debug(": reloading hostapd\n");
			rc = kill(hostap_pids[i], SIGHUP);
		}
		if (rc != 0) {
			debug(": starting hostapd\n");
			hostap_pids[i] = daemonize(argv);
		}
	} else
		debug(": Failed to get card number\n");

	EXIT();
	return 0;
}

static int supplicant_config(const char *device, struct tr069_value_table *ift)
{
	const char *ssid, *passphrase;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Enable */
	if (!tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Enable)) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	ssid = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.KeyPassphrase */
	passphrase=tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_KeyPassphrase);

	/* FIXME: ssid and passphrase may contain magic shell characters that may be exploited */
	vasystem("wpa_passphrase \"%s\" \"%s\" >/var/etc/wpa.conf", ssid, passphrase);

/*	vasystem("brctl setfd br0 1\n");*/

/*	vasystem("wpa_supplicant -B -bbr0 -Dmadwifi -i%s -c/var/etc/wpa.conf\n", device);*/
	vasystem("wpa_supplicant -B -Dmadwifi -i%s -c/var/etc/wpa.conf\n", device);

	EXIT();
	return 0;
}

static int power_config(const char *device, struct tr069_value_table *ift)
{
	int power;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.X_TPOSS_TxPower */
	power = (int)tr069_get_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_X_TPOSS_TxPower) ? : 63;
	vasystem("iwconfig %s txpower %umW", device, power);

	/*
	 * get actual power
	 */
	if ((power = get_txpower(device)) > 0)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.X_TPOSS_TxPower */
		tr069_set_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_X_TPOSS_TxPower, (unsigned)power);

	EXIT();
	return 0;
}

static int setup_ap(const char *device, struct tr069_value_table *ift)
{
	const char *ssid, *keypassphrase;
	char hexkey[33];/*atheros chipset supports up to 128 bit hexkeys*/
	int encrypt;
	char buf[32];
	const char *possible_chans;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	ssid = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Channel */
	ap_channel = tr069_get_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Channel);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.PossibleChannels */
	possible_chans = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_PossibleChannels) ? : "";

	snprintf(buf, sizeof(buf), "%u", ap_channel);
	if (*possible_chans && !tr069_listcontains((char *)possible_chans, buf)) {
		sscanf(possible_chans, "%u", &ap_channel);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Channel */
		tr069_set_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Channel, ap_channel);
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BasicEncryptionModes */
	encrypt = tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BasicEncryptionModes);

	if (!ssid || !ap_channel) {
		debug(": Wireless interface has been misconfigured.");
		EXIT();
		return -1;
	}

	iwconfig_exec(device, "essid", ssid);

	if (encrypt) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.KeyPassphrase */
		keypassphrase = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_KeyPassphrase);
		if (!keypassphrase || (keypassphrase && strlen(keypassphrase) < 5)) {
			debug(": no valid key has been set\n");
		} else {
			for(unsigned int c = 0; (c < strlen(keypassphrase) && c < 17); c++)
				snprintf(hexkey + (2 * c), 3, "%02hhx", keypassphrase[c]);
			vasystem("iwconfig %s key %s", device, hexkey);
		}
	}

	vasystem("iwconfig %s channel %d", device, ap_channel);

	/*enable WDS parent*/
	vasystem("iwpriv %s wds 1", device);

	EXIT();
	return 0;
}

static int setup_bridge(const char *device, struct tr069_value_table *ift)
{
	const char *peermac;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.PeerBSSID */
	peermac = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_PeerBSSID);
	if (!peermac) {
		EXIT();
		return -1;
	}

	vasystem("iwconfig %s channel %d", device, ap_channel);
	va_invoke_executable("/usr/sbin/iwpriv", device, "wds_add", peermac);

	EXIT();
	return 0;
}

static int setup_sta(const char *device, struct tr069_value_table *ift)
{
	const char *ssid, *keypassphrase;
	char hexkey[33];/*atheros chipset supports up to 128 bit hexkeys*/

	int encrypt;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	ssid = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID);

	iwconfig_exec(device, "essid", ssid);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BasicEncryptionModes */
	encrypt = tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BasicEncryptionModes);

	if (encrypt) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.KeyPassphrase */
		keypassphrase = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_KeyPassphrase);
		if (!keypassphrase || (keypassphrase && strlen(keypassphrase) < 5)) {
			debug(": no valid key has been set\n");
		} else {
			for(unsigned int c = 0; (c < strlen(keypassphrase) && c < 17); c++)
				snprintf(hexkey + (2 * c), 3, "%02hhx", keypassphrase[c]);
			vasystem("iwconfig %s key %s", device, hexkey);
		}
	}

	EXIT();
	return 0;
}

static int setup_repeater(const char *device, struct tr069_value_table *ift)
{
	int r;
	ENTER();
	r = setup_sta(device, ift);
	vasystem("iwpriv %s wds 1\n", device);
	EXIT();
	return r;
}

int madwifi_ifup(const char *device, const tr069_selector sel)
{
	int rc = -1;
	cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_e opmode;
	cwmp___IGD_LANDev_i_WLANCfg_j_BeaconType_e beacontype;
	struct tr069_value_table *ift;

	char *channels;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice */
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

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Standard */
	switch (tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Standard)) {
	case cwmp___IGD_LANDev_i_WLANCfg_j_Standard_a:
		vasystem("iwpriv %s mode 11a", device);
		break;
	case cwmp___IGD_LANDev_i_WLANCfg_j_Standard_b:
		vasystem("iwpriv %s mode 11b", device);
		break;
	case cwmp___IGD_LANDev_i_WLANCfg_j_Standard_g:
		vasystem("iwpriv %s mode 11g", device);
		break;
	}

	channels = get_possible_channels(device);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.PossibleChannels */
	tr069_set_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_PossibleChannels, channels);
	free(channels);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.DeviceOperationMode */
	opmode = tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_DeviceOperationMode);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BeaconType */
	beacontype = tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BeaconType);

	if (beacontype != cwmp___IGD_LANDev_i_WLANCfg_j_BeaconType_None) {
		/* If beacontype is unspecified, the interface will not be activated! */
		switch (opmode) {
		case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_InfrastructureAccessPoint:
			rc = setup_ap(device, ift);
			if (!rc && beacontype == cwmp___IGD_LANDev_i_WLANCfg_j_BeaconType_WPA)
				rc = hostap_config(device, ift);
			break;

		case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_WirelessBridge:
			rc = setup_bridge(device, ift);
			break;

		case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_WirelessRepeater:
			rc = setup_repeater(device, ift);
			if (!rc && beacontype == cwmp___IGD_LANDev_i_WLANCfg_j_BeaconType_WPA)
				rc = supplicant_config(device, ift);
			break;

		case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_WirelessStation:
			rc = setup_sta(device, ift);
			if (!rc && beacontype == cwmp___IGD_LANDev_i_WLANCfg_j_BeaconType_WPA)
				rc = supplicant_config(device, ift);
			break;
		}
	}

	if (rc) {
		EXIT();
		return rc;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.ClientIsolation */
	int cliso = tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_ClientIsolation);
	vasystem("iwpriv %s ap_bridge %d", device, cliso ? 0 : 1);

	/* the interface is ready to go, add it to it's lan bridge */
	tr069_selector if_sel;

	memcpy(if_sel, sel, sizeof(if_sel));
	if_sel[3] = 0;
	if_add2LANdevice(device, if_sel);

#if defined (WITH_BCM63XX)
	sys_echo("/proc/led", "%s\n", "g28on");
#endif

	power_config(device, ift);

	EXIT();
	return 0;
}

void madwifi_ifdown(int card, int ifc)
{
	char iface[20];
	int i;

	get_ath_iface(card, ifc, iface, sizeof(iface));

	lan_ipdown(iface);
	if_linkdown(iface);

	i = (card - 1) * VAP_MAX + ifc - 1;
	if (hostap_pids[i] > 0)
		kill(hostap_pids[i], SIGTERM);
}

void madwifi_destroy_if(int card, int ifc)
{
	char iface[20];

	get_ath_iface(card, ifc, iface, sizeof(iface));
	vasystem("wlanconfig %s destroy", iface);
}

#if defined (WITH_BCM63XX)
static inline void netgear_clone_mac(const char *wifi)
{
        int s;
        struct ifreq ifr;
        char *ret = NULL;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
                perror("socket(AF_INET)");
                return;
        }

        memset(&ifr, 0, sizeof(ifr));

        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
        if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                vasystem("ifconfig %s hw ether %02x:%02x:%02x:%02x:%02x:%02x",
			 wifi,
			 (unsigned char)(ifr.ifr_hwaddr.sa_data[0] & 0xff),
			 (unsigned char)(ifr.ifr_hwaddr.sa_data[1] & 0xff),
			 (unsigned char)(ifr.ifr_hwaddr.sa_data[2] & 0xff),
			 (unsigned char)(ifr.ifr_hwaddr.sa_data[3] & 0xff),
			 (unsigned char)(ifr.ifr_hwaddr.sa_data[4] & 0xff),
			 (unsigned char)(ifr.ifr_hwaddr.sa_data[5] & 0xff));
        }

        close(s);
}
#endif

static uint32_t idmap = 0;

int madwifi_create_if(const char *device, const tr069_selector sel)
{
	char buf[PATH_MAX];
	char iface[20];
	int ifc_num;
	cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_e opmode;

	const char *regdomain;
	unsigned int country_code;
	int outdoor;

	struct tr069_value_table *ift;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice */
	debug("DeviceType: %d\n", sel[1]);
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

	ifc_num = ffs(~(idmap)) - 1;
	idmap |= 1 << ifc_num;
	snprintf(iface, sizeof(iface), WLAN_DEVICE, ifc_num);

	if_add2ifmap(iface, sel);

#if defined (WITH_BCM63XX)
	netgear_clone_mac(device);
#endif

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.DeviceOperationMode */
	opmode = tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_DeviceOperationMode);

	switch (opmode) {
	case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_InfrastructureAccessPoint:
		vasystem("wlanconfig %s create wlandev %s wlanmode ap", iface, device);
		break;

	case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_WirelessBridge:
		vasystem("wlanconfig %s create wlandev %s wlanmode wds", iface, device);
		break;

	case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_WirelessRepeater:
		vasystem("wlanconfig %s create wlandev %s wlanmode sta nosbeacon", iface, device);
		break;

	case cwmp___IGD_LANDev_i_WLANCfg_j_DeviceOperationMode_WirelessStation:
		vasystem("wlanconfig %s create wlandev %s wlanmode sta", iface, device);
		break;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.RegulatoryDomain */
	regdomain = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_RegulatoryDomain);

	if (iso3166_decode_regdomain(regdomain, &country_code, &outdoor)) {
		country_code = 0 /* default: USA */;
		outdoor = 0;
	}
	debug(": country_code=%u, outdoor=%d", country_code, outdoor);

	/* FIXME: regdomain == 0 may not allow all countrycodes */
	snprintf(buf, sizeof(buf), "/proc/sys/dev/%s/regdomain", device);
	sys_echo(buf, "%u", 0x0);

	snprintf(buf, sizeof(buf), "/proc/sys/dev/%s/countrycode", device);
	sys_echo(buf, "%u", country_code);

	if (sys_scan(buf, "%u", &country_code) == 1 && country_code == 0)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.RegulatoryDomain */
		tr069_set_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_RegulatoryDomain,
				       outdoor > 0 ? "USO" : "USI");

	snprintf(buf, sizeof(buf), "/proc/sys/dev/%s/outdoor", device);
	sys_echo(buf, "%d", outdoor > 0);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.X_TPOSS_AntennaSelection */
	unsigned int asid = tr069_get_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_X_TPOSS_AntennaSelection);
	if (asid > 0) {
		snprintf(buf, sizeof(buf), "/proc/sys/dev/%s/txantenna", device);
		sys_echo(buf, "%u", asid - 1);
		snprintf(buf, sizeof(buf), "/proc/sys/dev/%s/rxantenna", device);
		sys_echo(buf, "%u", asid - 1);

		snprintf(buf, sizeof(buf), "/proc/sys/dev/%s/diversity", device);
		sys_echo(buf, "%u", asid <= 1);
	}

	EXIT();
	return 0;
}

