#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

#include <iwlib.h>
#include <wlioctl.h>

#define SDEBUG
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"

#include "ifup.h"
#include "l3forward.h"
//#include "nvram.h"
#include <bcmnvram.h>

#define	ADD_VIF_RETRIES	5

static int skfd = -1;

#define TRACE

#if defined(TRACE)

static char trace_prefix[128];

#define TRACE_PARM(...)              __VA_ARGS__, const char *_caller, int _line, const char *_prefix __attribute__ ((unused))
#define TRACE_FUNC(...)              __VA_ARGS__, __FUNCTION__, __LINE__, NULL
#define TRACE_CALL(prefix, ...)      __VA_ARGS__, _caller, _line, prefix

const char *trace(const char *fmt, ...)
     __attribute__ ((__format__ (__printf__, 1, 2)));

const char *trace(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(trace_prefix, sizeof(trace_prefix), fmt, args);
	va_end(args);

	return trace_prefix;
}

#define trace_log(format, ...)       syslog(LOG_KERN|LOG_NOTICE|LOG_FACMASK|LOG_DAEMON, "%s:%d %s" format, _caller, _line, _prefix ? _prefix : " ", ## __VA_ARGS__)
#define trace_debug(format, ...)     do { fprintf(stderr, "%s:%d %s" format, _caller, _line, _prefix ? _prefix : " ", ## __VA_ARGS__); fflush(stderr); } while (0)

#else

#define TRACE_PARM(...)              __VA_ARGS__
#define TRACE_FUNC(...)              __VA_ARGS__
#define TRACE_CALL(prefix, ...)      __VA_ARGS__
#define trace(format, ...)           NULL
#define trace_log(format, ...)       do {} while (0)
#endif

static const char *prefix;
static char buffer[128];

static char *wl_var(char *name)
{
        sprintf(buffer, "%s_%s", prefix, name);
        return buffer;
}

#if 0
static char *vif_var(int vif, char *name)
{
        if (vif == 0)
                return wl_var(name);

        sprintf(buffer, "%s.%d_%s", prefix, vif, name);
        return buffer;
}
#endif

static int nvram_enabled(char *name)
{
        return (nvram_match(name, "1") || nvram_match(name, "on") || nvram_match(name, "enabled") || nvram_match(name, "true") || nvram_match(name, "yes") ? 1 : 0);
}

#if 0
static int nvram_disabled(char *name)
{
        return (nvram_match(name, "0") || nvram_match(name, "off") || nvram_match(name, "disabled") || nvram_match(name, "false") || nvram_match(name, "no") ? 1 : 0);
}
#endif

static int ether_atoe(const char *a, unsigned char *e)
{
        char *c = (char *) a;
        int i = 0;

        memset(e, 0, ETHER_ADDR_LEN);
        for (;;) {
                e[i++] = (unsigned char) strtoul(c, &c, 16);
                if (!*c++ || i == ETHER_ADDR_LEN)
                        break;
        }
        return (i == ETHER_ADDR_LEN);
}

/*------------------------------------------------------------------*/
/*
 * Macro to handle errors when setting WE
 * Print a nice error message and exit...
 * We define them as macro so that "return" do the right thing.
 * The "do {...} while(0)" is a standard trick
 */
#define ERR_SET_EXT(rname, request) \
	fprintf(stderr, "Error for wireless request \"%s\" (%X) :\n", \
		rname, request)

/*------------------------------------------------------------------*/
/*
 * Wrapper to push some Wireless Parameter in the driver
 * Use standard wrapper and add pretty error message if fail...
 */
#define IW_SET_EXT_ERR(skfd, ifname, request, wrq, rname) \
	do { \
	if(iw_set_ext(skfd, ifname, request, wrq) < 0) { \
		ERR_SET_EXT(rname, request); \
		fprintf(stderr, "    SET failed on device %-1.16s ; %s.\n", \
			ifname, strerror(errno)); \
	} } while(0)

/*------------------------------------------------------------------*/
/*
 * Wrapper to extract some Wireless Parameter out of the driver
 * Use standard wrapper and add pretty error message if fail...
 */
#define IW_GET_EXT_ERR(skfd, ifname, request, wrq, rname) \
	do { \
	if(iw_get_ext(skfd, ifname, request, wrq) < 0) { \
		ERR_SET_EXT(rname, request); \
		fprintf(stderr, "    GET failed on device %-1.16s ; %s.\n", \
			ifname, strerror(errno)); \
	} } while(0)

/*------------------------------------------------------------------*/

/* Quarter dBm units to mW
 * Table starts at QDBM_OFFSET, so the first entry is mW for qdBm=153
 * Table is offset so the last entry is largest mW value that fits in
 * a uint16.
 */

#define QDBM_OFFSET 153
#define QDBM_TABLE_LEN 40

/* Smallest mW value that will round up to the first table entry, QDBM_OFFSET.
 * Value is ( mW(QDBM_OFFSET - 1) + mW(QDBM_OFFSET) ) / 2
 */
#define QDBM_TABLE_LOW_BOUND 6493

/* Largest mW value that will round down to the last table entry,
 * QDBM_OFFSET + QDBM_TABLE_LEN-1.
 * Value is ( mW(QDBM_OFFSET + QDBM_TABLE_LEN - 1) + mW(QDBM_OFFSET + QDBM_TABLE_LEN) ) / 2.
 */
#define QDBM_TABLE_HIGH_BOUND 64938

static const uint16 nqdBm_to_mW_map[QDBM_TABLE_LEN] = {
/* qdBm:        +0		+1		+2		+3		+4		+5		+6		+7	*/
/* 153: */      6683,	7079,	7499,	7943,	8414,	8913,	9441,	10000,
/* 161: */      10593,	11220,	11885,	12589,	13335,	14125,	14962,	15849,
/* 169: */      16788,	17783,	18836,	19953,	21135,	22387,	23714,	25119,
/* 177: */      26607,	28184,	29854,	31623,	33497,	35481,	37584,	39811,
/* 185: */      42170,	44668,	47315,	50119,	53088,	56234,	59566,	63096
};

unsigned char mw_to_qdbm(uint16 mw)
{
	int qdbm;
	int offset;
	uint mw_uint = mw;
	uint boundary;

	/* handle boundary case */
	if (mw_uint <= 1)
		return 0;

	offset = QDBM_OFFSET;

	/* move mw into the range of the table */
	while (mw_uint < QDBM_TABLE_LOW_BOUND) {
		mw_uint *= 10;
		offset -= 40;
	}

	for (qdbm = 0; qdbm < QDBM_TABLE_LEN-1; qdbm++) {
		boundary = nqdBm_to_mW_map[qdbm] + (nqdBm_to_mW_map[qdbm+1] - nqdBm_to_mW_map[qdbm])/2;
		if (mw_uint < boundary) break;
	}

	qdbm += (unsigned char)offset;

	return(qdbm);
}

static void init_ctrl_socket(void)
{
	if (skfd > 0)
		return;

	skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		perror("socket(AF_INET)");
}

static int _bcom_ioctl(TRACE_PARM(const char *ifname, int cmd, void *buf, int len))
{
	struct ifreq ifr;
	wl_ioctl_t ioc;
	int ret;

	ioc.cmd = cmd;
	ioc.buf = buf;
	ioc.len = len;

	ifr.ifr_data = (caddr_t) &ioc;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	/*	trace_debug("doing IOCTL %d\n", cmd); */
	ret = ioctl(skfd, SIOCDEVPRIVATE, &ifr);

	if (ret < 0)
		trace_log("IOCTL %d failed: %s\n", cmd, strerror(errno));

	return ret;
}
#define bcom_ioctl(ifname, cmd, buf, len) _bcom_ioctl(TRACE_FUNC(ifname, cmd, buf, len))

static int _bcom_set_var(TRACE_PARM(const char *ifname, char *var, void *val, size_t len))
{
	char buf[8192];

	if (strlen(var) + 1 > sizeof(buf) || len > sizeof(buf))
		return -1;

	bzero(buf, sizeof(buf));
	strcpy(buf, var);
	memcpy(&buf[strlen(var) + 1], val, len);

	return _bcom_ioctl(TRACE_CALL(trace("SET_VAR %s ", var), ifname, WLC_SET_VAR, buf, sizeof(buf)));
}
#define bcom_set_var(ifname, var, val, len) _bcom_set_var(TRACE_FUNC(ifname, var, val, len))

#if 0
static int _bcom_get_var(TRACE_PARM(const char *ifname, char *var, void *buf, size_t len))
{
	if (strlen(var) + 1 > sizeof(buf) || len > sizeof(buf))
		return -1;

	bzero(buf, sizeof(buf));
	strcpy(buf, var);

	return _bcom_ioctl(TRACE_CALL(trace("GET_VAR %s ", var), ifname, WLC_GET_VAR, buf, sizeof(buf)));
}
#define bcom_get_var(ifname, var, buf, len) _bcom_get_var(TRACE_FUNC(ifname, var, buf, len))
#endif

static int _bcom_set_bss_var(TRACE_PARM(const char *ifname, int bss, char *var, void *val, size_t len))
{
	char buf[8192];
	int i = 0;

	bzero(buf, sizeof(buf));
	if (strlen(var) + len + 8 > sizeof(buf) || len > sizeof(buf))
		return -1;

	// "bsscfg:<name>\x00" <bss> <data>
	i = sprintf(buf, "bsscfg:%s", var);
	buf[i++] = 0;

	memcpy(buf + i, &bss, sizeof(uint32_t));
	i += sizeof(uint32_t);

	memcpy(buf + i, val, len);
	i += len;

	return _bcom_ioctl(TRACE_CALL(trace("SET_BSS_VAR %s ", var), ifname, WLC_SET_VAR, buf, i));
}
#define bcom_set_bss_var(ifname, bss, var, val, len) _bcom_set_bss_var(TRACE_FUNC(ifname, bss, var, val, len))

static int _bcom_get_bss_var(TRACE_PARM(const char *ifname, int bss, char *var, void *val, size_t len))
{
	char buf[8192];
	int i = 0, ret;

	bzero(buf, sizeof(buf));
	if (strlen(var) + len + 8 > sizeof(buf) || len > sizeof(buf))
		return -1;

	// "bsscfg:<name>\x00" <bss> <data>
	i = sprintf(buf, "bsscfg:%s", var);
	buf[i++] = 0;

	memcpy(buf + i, &bss, sizeof(bss));
	i += sizeof(bss);

	ret = _bcom_ioctl(TRACE_CALL(trace("GET_BSS_VAR %s ", var), ifname, WLC_GET_VAR, buf, i));

	if (ret == 0)
		memcpy(val, buf, len);

	return ret;
}
#define bcom_get_bss_var(ifname, bss, var, val, len) _bcom_get_bss_var(TRACE_FUNC(ifname, bss, var, val, len))

static inline int _bcom_set_bss_int_var(TRACE_PARM(const char *ifname, int bss, char *var, int val))
{
	return _bcom_set_bss_var(TRACE_CALL(NULL, ifname, bss, var, &val, sizeof(val)));
}
#define bcom_set_bss_int_var(ifname, bss, var, val) _bcom_set_bss_int_var(TRACE_FUNC(ifname, bss, var, val))

static inline int _bcom_set_int_var(TRACE_PARM(const char *ifname, char *var, int val))
{
	return _bcom_set_var(TRACE_CALL(NULL, ifname, var, &val, sizeof(val)));
}
#define bcom_set_int_var(ifname, var, val) _bcom_set_int_var(TRACE_FUNC(ifname, var, val))

static inline int _bcom_set_bss_int(TRACE_PARM(const char *ifname, int bss, char *var, int val))
{
	return _bcom_set_bss_var(TRACE_CALL(NULL, ifname, bss, var, &val, sizeof(val)));
}
#define bcom_set_bss_int(ifname, bss, var, val) _bcom_set_bss_int(TRACE_FUNC(ifname, bss, var, val))

static inline int _bcom_set_int(TRACE_PARM(const char *ifname, int request, int val))
{
	return _bcom_ioctl(TRACE_CALL(trace("SET_INT %d = %d ", request, val), ifname, request, &val, sizeof(val)));
}
#define bcom_set_int(ifname, request, val) _bcom_set_int(TRACE_FUNC(ifname, request, val))

static inline int _bcom_get_int(TRACE_PARM(const char *ifname, int request, int *val))
{
	return _bcom_ioctl(TRACE_CALL(trace("GET_INT %d ", request), ifname, request, val, sizeof(int)));
}
#define bcom_get_int(ifname, request, val) _bcom_get_int(TRACE_FUNC(ifname, request, val))

#if 0
static int is_new_bcom(const char *ifname)
{
	char buf[8192];

	bzero(buf, 8192);
	bcom_ioctl(ifname, WLC_DUMP, buf, 8192);

	if (strstr(buf, "3.90"))
		return 0;

	return 1;
}
#endif

static void stop_bcom(const char *ifname)
{
	int val = 0;

	ENTER();

	if (bcom_get_int(ifname, WLC_GET_MAGIC, &val) < 0) {
		EXIT();
		return;
	}

#if 0
	wlc_ssid_t ssid;

	ssid.SSID_len = 0;
	ssid.SSID[0] = 0;
	bcom_ioctl(ifname, WLC_SET_SSID, &ssid, sizeof(ssid));
#endif
	bcom_ioctl(ifname, WLC_DOWN, NULL, 0);

	EXIT();
}

static void start_bcom(const char *ifname)
{
	int val = 0;

	ENTER();

	if (bcom_get_int(ifname, WLC_GET_MAGIC, &val) < 0) {
		EXIT();
		return;
	}

	bcom_set_int(ifname, WLC_UP, val);
	EXIT();
}

static void debug_bcom_vif(const char *ifname, int vif)
{
	int i;
	wlc_ssid_t ssid;

	i = bcom_get_bss_var(ifname, vif, "ssid", &ssid, sizeof(ssid));
	if (i == 0)
		debug("(): ssid: %d, --%.*s--\n", i, ssid.SSID_len, ssid.SSID);
}


#if 0
static int setup_bcom_wds(char *ifname)
{
	char buf[8192];
	char wbuf[80];
	char *v;
	int wds_enabled = 0;

	if (v = nvram_get(wl_var("wds"))) {
		struct maclist *wdslist = (struct maclist *) buf;
		struct ether_addr *addr = wdslist->ea;
		char *next;

		memset(buf, 0, 8192);
		foreach(wbuf, v, next) {
			if (ether_atoe(wbuf, addr->ether_addr_octet)) {
				wdslist->count++;
				addr++;
				wds_enabled = 1;
			}
		}
		bcom_ioctl(ifname, WLC_SET_WDSLIST, buf, sizeof(buf));
	}
	return wds_enabled;
}
#endif

struct wl_param {
	tr069_selector sel;
	char           device[];
};

static void *wl_watchdog_thread(void *arg)
{
	struct wl_param *wlp;
	wlc_ssid_t ssid;
	int i;
	const char *v;
	unsigned char buf[8192];

	ENTER();
#if 0
	FILE *f;
	char *v, *next;
	unsigned char buf[8192], buf2[8192], wbuf[80], *p, *tmp;
	int wds = 0, i, j, restart_wds;

	v = nvram_safe_get(wl_var("wds"));
	memset(buf2, 0, 8192);
	p = buf2;
	foreach(wbuf, v, next) {
		if (ether_atoe(wbuf, p)) {
			p += 6;
			wds++;
		}
	}
#endif

	wlp = (struct wl_param *)arg;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	v = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							   cwmp__IGD_LANDevice,
							   wlp->sel[2],
							   cwmp__IGD_LANDev_i_WLANConfiguration,
							   wlp->sel[4],
							   cwmp__IGD_LANDev_i_WLANCfg_j_SSID, 0 });
	ssid.SSID_len = strlen(v);
	strncpy(ssid.SSID, v, 32);
	debug("(): device: %s, ssid: %s\n", wlp->device, v);

	for (;;) {
		sleep(5);

		/* client mode */
		bcom_get_int(wlp->device, WLC_GET_AP, &i);
		if (!i) {
			unsigned char *bssid;
			int b;

			memset(buf, 0, 8192);
			strcpy(buf, "sta_info");
			bssid = buf + strlen(buf) + 1;

			b = i = 0;
			if (bcom_ioctl(wlp->device, WLC_GET_BSSID, bssid, 6) < 0) {
				debug("(): get bssid failed\n");
				b = i = 1;
			} else if (memcmp(bssid, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
				debug("(): ssid is zero\n");
				b = i = 1;
			} else if (bcom_ioctl(wlp->device, WLC_GET_VAR, buf, 8192) < 0) {
				debug("(): get sta_info failed\n");
				i = 1;
			} else {
				sta_info_t *sta = (sta_info_t *) buf;

				if ((sta->flags & 0x18) != 0x18)
					i = 1;

				if (i)
					debug("(): buf: %02x,%02x,%02x,%02x, ver: %d, len: %d, cap: %d, flags: %x, idle: %d, rateset: %d, in: %d, lii: %d\n",
					      buf[0], buf[1], buf[2], buf[2],
					      sta->ver, sta->len, sta->cap, sta->flags, sta->idle, sta->rateset.count, sta->in, sta->listen_interval_inms);

				/*
				if (sta->idle > 60)
					i = 1;
				*/
			}
#if 0
			if (i) {
				debug("(): set ssid: %s\n", ssid.SSID);
				bcom_ioctl(wlp->device, WLC_SET_SSID, &ssid, sizeof(ssid));
			}
#endif
#if 0
			if (b) {
				/* REASSOC to ANY */
				/* FIXME: if we are not in Infrastructure mode, this has to be WLC_SET_BSSID */

				debug("(): reassoc\n");

				memset(bssid, 0xff, 6);
				bcom_ioctl(wlp->device, WLC_REASSOC, bssid, 6);
			}
#endif
		}

#if 0
		/* wds */
		p = buf2;
		restart_wds = 0;
		for (i = 0; i < wds; i++) {
			memset(buf, 0, 8192);
			strcpy(buf, "sta_info");
			memcpy(buf + strlen(buf) + 1, p, 6);
			if (bcom_ioctl(ifname, WLC_GET_VAR, buf, 8192) < 0) {
			} else {
				sta_info_t *sta = (sta_info_t *) (buf + 4);
				if (!(sta->flags & 0x40)) {
				} else {
					if (sta->idle > 120)
						restart_wds = 1;
				}
			}
			p += 6;
		}
		if (restart_wds)
			setup_bcom_wds(ifname);
#endif
	}
	free(arg);
	EXIT();

	return NULL;
}

static pthread_t wdt_tid;

static void start_watchdog(const char *device, tr069_selector sel)
{
	struct wl_param *wlp;

	debug("creating wl watchdog thread\n");

	wlp = malloc(sizeof(struct wl_param) + strlen(device) + 1);
	if (!wlp)
		return;
	tr069_selcpy(wlp->sel, sel);
	strcpy(wlp->device, device);

	pthread_create(&wdt_tid, NULL, wl_watchdog_thread, wlp);
	pthread_detach(wdt_tid);
}

#if 0
static void setup_bcom_wpa_keys(const char *ifname, int vif, struct tr069_value_table *ift)
{
	int i;
	struct tr069_value_table *psk;

	ENTER();

	/** VAR: (tbd) InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.PreSharedKey */
	psk = tr069_get_table_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_PreSharedKey);
	if (!psk) {
		EXIT();
		return;
	}

	for (i = 0; i < psk->size; i++) {
		struct tr069_value_table *key;

		// key = tr069_get_table_by_id(psk->values[i], cwmp__IGD_LANDev_i_WLANCfg_j_PSK_k_PreSharedKey);

	}

	EXIT();
}
#endif

static void setup_bcom_wep_keys(const char *ifname, int vif, struct tr069_value_table *ift)
{
	int i;
	struct tr069_value_table *psk;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WEPKey */
	psk = tr069_get_table_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_WEPKey);
	if (!psk) {
		EXIT();
		return;
	}

	for (i = 0; i < psk->size; i++) {
		wl_wsec_key_t k;
		char hex[] = "XX";
		unsigned char *kdata = k.data;
		const unsigned char *kstr;
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WEPKey.{i} */

		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WEPKey.{i}.WEPKey */
		kstr = tr069_get_string_by_id(tr069_get_table_by_index(psk, i), cwmp__IGD_LANDev_i_WLANCfg_j_WEP_k_WEPKey);

		bzero(&k, sizeof(k));
		k.len = strlen(kstr);
		if ((k.len == 10) || (k.len == 26)) {
			k.index = i;
			k.len = 0;
			while (*kstr != 0) {
				strncpy(hex, kstr, 2);
				*kdata = (unsigned char) strtoul(hex, NULL, 16);
				kstr += 2;
				kdata++;
				k.len++;
			}
			debug("Adding WEP key %d to VIF %d: %.*s\n", i, vif, k.len, k.data);
		} else {
			k.len = 0;
		}

		if ((k.len > 0) &&
		    /** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WEPKey.{i}.WEPKeyIndex */
		    ((i + 1) == tr069_get_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_WEPKeyIndex)))
			k.flags = WL_PRIMARY_KEY;

		bcom_set_bss_var(ifname, vif, "wsec_key", &k, sizeof(k));
	}

	EXIT();
}


#define b_Basic		0x01
#define b_WPA		0x02
#define b_11i		0x04

static int beacon_t[] = {
	0,				/* None */
	b_Basic,			/* Basic */
	b_WPA,				/* WPA */
	b_11i,				/* 11i */
	b_Basic | b_WPA,		/* BasicandWPA */
	b_Basic | b_11i,		/* Basicand11i */
	b_WPA | b_11i,			/* WPAand11i */
	b_Basic | b_WPA | b_11i		/* BasicandWPAand11i */
};

/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BasicEncryptionModes */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAEncryptionModes */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iEncryptionModes */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAEncryptionModes */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iEncryptionModes */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iEncryptionModes */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iEncryptionModes */

static int crypt_mode_t[] = {
	0,									/* None */
	cwmp__IGD_LANDev_i_WLANCfg_j_BasicEncryptionModes,			/* Basic */
	cwmp__IGD_LANDev_i_WLANCfg_j_WPAEncryptionModes,			/* WPA */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iEncryptionModes,			/* 11i */
	cwmp__IGD_LANDev_i_WLANCfg_j_WPAEncryptionModes,			/* BasicandWPA */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iEncryptionModes,			/* Basicand11i */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iEncryptionModes,			/* WPAand11i */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iEncryptionModes			/* BasicandWPAand11i */
};

static int crypt_type_t[] = {
	0,
	WEP_ENABLED,								/* WEPEncryption */
	TKIP_ENABLED,								/* TKIPEncryption */
	WEP_ENABLED | TKIP_ENABLED,						/* WEPandTKIPEncryption */
	AES_ENABLED,								/* AESEncryption */
	WEP_ENABLED | AES_ENABLED,						/* WEPandAESEncryption */
	TKIP_ENABLED | AES_ENABLED,						/* TKIPandAESEncryption */
	WEP_ENABLED | TKIP_ENABLED | AES_ENABLED				/* WEPandTKIPandAESEncryption */
};

/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BasicAuthenticationMode */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAAuthenticationMode */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iAuthenticationMode */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAAuthenticationMode */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iAuthenticationMode */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iAuthenticationMode */
/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iAuthenticationMode */
static int auth_mode_t[] = {
	0,									/* None */
	cwmp__IGD_LANDev_i_WLANCfg_j_BasicAuthenticationMode,			/* Basic */
	cwmp__IGD_LANDev_i_WLANCfg_j_WPAAuthenticationMode,			/* WPA */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iAuthenticationMode,			/* 11i */
	cwmp__IGD_LANDev_i_WLANCfg_j_WPAAuthenticationMode,			/* BasicandWPA */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iAuthenticationMode,			/* Basicand11i */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iAuthenticationMode,			/* WPAand11i */
	cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iAuthenticationMode			/* BasicandWPAand11i */
};

static int wpa_auth_type_t[] = {
	WPA_AUTH_PSK,								/* PSKAuthentication */
	WPA_AUTH_UNSPECIFIED							/* EAPAuthentication */
};

static int ieee11i_auth_type_t[] = {
	WPA2_AUTH_PSK,								/* PSKAuthentication */
	WPA2_AUTH_UNSPECIFIED,							/* EAPAuthentication */
	WPA2_AUTH_UNSPECIFIED | WPA2_AUTH_PSK					/* EAPandPSKAuthentication */
};

static void setup_bcom_vif_sec(const char *ifname, int vif, struct tr069_value_table *ift)
{
	int val;
	int beacon;
	int crypt = 0;
	int auth = 0;

	ENTER();

	debug_bcom_vif(ifname, vif);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BeaconType */
	beacon = beacon_t[tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BeaconType)];

	if (beacon != 0) {
		crypt = crypt_mode_t[beacon] ? tr069_get_enum_by_id(ift, crypt_mode_t[beacon]) : 0;
		auth = auth_mode_t[beacon] ? tr069_get_enum_by_id(ift, auth_mode_t[beacon]) : 0;

		if (beacon != 1) {
			/* account for missing None choice in WPA and 11i */
			crypt++;
			auth++;
		}
	}
	debug("(): wsec: %x\n", crypt_type_t[crypt]);
	bcom_set_bss_int_var(ifname, vif, "wsec", crypt_type_t[crypt]);
	bcom_set_bss_int_var(ifname, vif, "wsec_restrict", crypt_type_t[crypt] ? 1 : 0);

	val = 0;
	if (beacon_t[beacon] & b_Basic) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BasicAuthenticationMode */
		debug("(): auth: %d\n", tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BasicAuthenticationMode) == 1);
		bcom_set_bss_int_var(ifname, vif, "auth",
				 tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BasicAuthenticationMode) == 1);
	}
	if (beacon_t[beacon] & b_WPA)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.WPAAuthenticationMode */
		val |= wpa_auth_type_t[tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_WPAAuthenticationMode)];
	if (beacon_t[beacon] & b_11i)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.IEEE11iAuthenticationMode */
		val |= ieee11i_auth_type_t[tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_IEEE11iAuthenticationMode)];

#if 0
	/* in WET mode with WPA only */
        if ((val & WPA_AUTH_PSK) || (val & WPA2_AUTH_PSK)) {
		* Enable in-driver WPA supplicant */
                wsec_pmk_t psk;
                char *key;

                if (((key = nvram_get(strcat_r(prefix, "wpa_psk", tmp))) != NULL)
                                && (strlen(key) < WSEC_MAX_PSK_LEN)) {
                        psk.key_len = (ushort) strlen(key);
                        psk.flags = WSEC_PASSPHRASE;
                        strcpy(psk.key, key);
                        WL_IOCTL(name, WLC_SET_WSEC_PMK, &psk, sizeof(psk));
                }
                wl_iovar_setint(name, "sup_wpa", 1);
        }
#endif

	debug("(): wpa_auth: %x\n", val);
	bcom_set_bss_int_var(ifname, vif, "wpa_auth", val);

        /* EAP Restrict */
	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BasicAuthenticationMode */
        val = ((val != 0) || tr069_get_enum_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BasicAuthenticationMode) == 1);
	debug("(): eap_restrict: %d\n", val);
        bcom_set_bss_int_var(ifname, vif, "eap_restrict", val);

	if (beacon_t[beacon] & b_Basic)
		setup_bcom_wep_keys(ifname, vif, ift);

	debug_bcom_vif(ifname, vif);

	EXIT();
}

static void setup_bcom_vif(const char *ifname, int vif, struct tr069_value_table *ift)
{
	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.BeaconAdvertisementEnabled */
	bcom_set_bss_int(ifname, vif, "closednet", !tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_BeaconAdvertisementEnabled));

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.ClientIsolation */
	bcom_set_bss_int(ifname, vif, "ap_isolate",
			 tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_ClientIsolation));

#if 0
	wlc_ssid_t ssid;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	strncpy(ssid.SSID,
		tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID),
		sizeof(ssid.SSID));
	ssid.SSID_len = strlen(ssid.SSID);
	ssid.SSID_len = ((ssid.SSID_len > sizeof(ssid.SSID)) ? sizeof(ssid.SSID) : ssid.SSID_len);

	if (vif == 0) {
		/* for the main interface, also try the WLC_SET_SSID call */
		bcom_ioctl(ifname, WLC_SET_SSID, &ssid, sizeof(ssid));
	}
	bcom_set_bss_var(ifname, vif, "ssid", &ssid, sizeof(ssid));

	debug("(): setting ssid for %d to: %s\n", vif, ssid.SSID);

	debug_bcom_vif(ifname, vif);
#endif

	EXIT();
}

static void start_bcom_vif(const char *ifname, int vif, struct tr069_value_table *ift)
{
	wlc_ssid_t ssid;
	int cfg[2];
	int i;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.SSID */
	strncpy(ssid.SSID,
		tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_SSID),
		sizeof(ssid.SSID));
	ssid.SSID_len = strlen(ssid.SSID);
	ssid.SSID_len = ((ssid.SSID_len > sizeof(ssid.SSID)) ? sizeof(ssid.SSID) : ssid.SSID_len);

	if (vif == 0) {
		/* for the main interface, also try the WLC_SET_SSID call */
		bcom_ioctl(ifname, WLC_SET_SSID, &ssid, sizeof(ssid));
	}
	bcom_set_bss_var(ifname, vif, "ssid", &ssid, sizeof(ssid));

	debug("(): setting ssid for %d to: %s\n", vif, ssid.SSID);

	debug_bcom_vif(ifname, vif);

	cfg[0] = vif;
	cfg[1] = 1;
	for (i = 0; i < ADD_VIF_RETRIES; i++) {
		if (bcom_set_var(ifname, "bss" , cfg, sizeof(cfg)) == 0) {
			debug("(): success on #%d\n", i);
			break;
		}
		usleep(1000 * 1000);
	}
	debug("(): retries #%d\n", i);
	EXIT();
}

static void setup_bcom_common(const char *ifname, struct tr069_value_table *ift)
{
	int val = 0;
	const char *v;

	assert(ift != NULL);

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.MaxBitRate */
	v = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_MaxBitRate);
	if (v && strncasecmp(v, "auto", 4) != 0) {
		val = atoi(v);
		if (val != 0) {
			bcom_set_int_var(ifname, "bg_rate", val * 2);
			bcom_set_int_var(ifname, "a_rate", val * 2);
		}
	}

	bcom_set_int_var(ifname, "rtsthresh", 2347);
	bcom_set_int_var(ifname, "fragthresh", 2346);

	bcom_set_int(ifname, WLC_SET_SPECT_MANAGMENT, SPECT_MNGMT_OFF);
	bcom_set_int(ifname, WLC_SET_REGULATORY, 0);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.RadioEnabled */
	val = !tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_RadioEnabled);
        val += WL_RADIO_SW_DISABLE << 16;
	bcom_set_int(ifname, WLC_SET_RADIO, val);

	/* Set Country */
	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.RegulatoryDomain */
	v = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_RegulatoryDomain);
	if (!v || !*v)
		v = "ALL";
	v = "IL0";
	bcom_ioctl(ifname, WLC_SET_COUNTRY, v, 4);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Channel */
	val = tr069_get_uint_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Channel);
	if (val > 0)
		bcom_set_int(ifname, WLC_SET_CHANNEL, val);

#if 0
	/* Set other options */
	val = nvram_enabled(wl_var("lazywds"));
	bcom_ioctl(ifname, WLC_SET_LAZYWDS, &val, sizeof(val));
#endif
	bcom_set_int(ifname, WLC_SET_LAZYWDS, 1);

	if ((v = nvram_get(wl_var("dtim"))))
		bcom_set_int(ifname, WLC_SET_DTIMPRD, atoi(v));

	if ((v = nvram_get(wl_var("bcn"))))
		bcom_set_int(ifname, WLC_SET_BCNPRD, atoi(v));

	if ((v = nvram_get(wl_var("antdiv"))))
		bcom_set_int(ifname, WLC_SET_ANTDIV, atoi(v));

	if ((v = nvram_get(wl_var("txant"))))
		bcom_set_int(ifname, WLC_SET_TXANT, atoi(v));

	bcom_set_int(ifname, WLC_SET_FAKEFRAG,nvram_enabled(wl_var("frameburst")));

	EXIT();
}

static void setup_bcom_gmode(const char *ifname, struct tr069_value_table *ift __attribute__ ((unused)))
{
	int val = 0;
	char *v;

	/* Set up G mode */
	bcom_get_int(ifname, WLC_GET_PHYTYPE, &val);
	if (val == 2) {
		int override = WLC_G_PROTECTION_OFF;
		int control = WLC_G_PROTECTION_CTL_OFF;

		if ((v = nvram_get(wl_var("gmode"))))
			val = atoi(v);
		else
			val = 1;

		if (val > 5)
			val = 1;

		bcom_set_int(ifname, WLC_SET_GMODE, val);

		if (nvram_match(wl_var("gmode_protection"), "auto")) {
			override = WLC_G_PROTECTION_AUTO;
			control = WLC_G_PROTECTION_CTL_OVERLAP;
		}
		if (nvram_enabled(wl_var("gmode_protection"))) {
			override = WLC_G_PROTECTION_ON;
			control = WLC_G_PROTECTION_CTL_OVERLAP;
		}

		override = WLC_G_PROTECTION_AUTO;
		control = WLC_G_PROTECTION_CTL_OVERLAP;

		bcom_set_int(ifname, WLC_SET_GMODE_PROTECTION_CONTROL, control);
		bcom_set_int(ifname, WLC_SET_GMODE_PROTECTION_OVERRIDE, override);

		if (val == 0) {
			if (nvram_match(wl_var("plcphdr"), "long"))
				val = WLC_PLCP_AUTO;
			else
				val = WLC_PLCP_SHORT;

			bcom_set_int(ifname, WLC_SET_PLCPHDR, val);
		}
	}
}

/* Copy each token in wordlist delimited by comma into word */
#define foreach(word, wordlist, next) \
        for (next = &wordlist[strspn(wordlist, ",")], \
             strncpy(word, next, sizeof(word)), \
             word[strcspn(word, ",")] = '\0', \
             word[sizeof(word) - 1] = '\0', \
             next = strchr(next, ','); \
             strlen(word); \
             next = next ? &next[strspn(next, ",")] : "", \
             strncpy(word, next, sizeof(word)), \
             word[strcspn(word, ",")] = '\0', \
             word[sizeof(word) - 1] = '\0', \
             next = strchr(next, ','))

static void setup_bcom_wds(const char *ifname, struct tr069_value_table *ift)
{
	char buf[8192];
	char wbuf[80];
	char *v;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.PeerBSSID */
	v = tr069_get_string_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_PeerBSSID);

	struct maclist *wdslist = (struct maclist *) buf;
	struct ether_addr *addr = wdslist->ea;
	char *next;

	memset(buf, 0, 8192);
	foreach(wbuf, v, next) {
		if (ether_atoe(wbuf, addr->ether_addr_octet)) {
			wdslist->count++;
			addr++;
		}
	}
	bcom_ioctl(ifname, WLC_SET_WDSLIST, buf, sizeof(buf));
}

static void setup_bcom_mac_acl(const char *ifname, tr069_selector sel)
{
	const char *mac_acl;
	struct maclist *mac_list;
	struct ether_addr *addr;
	char *buf, wbuf[80], *v = NULL, *next;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.AllowedMACAddresses */
	mac_acl = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								 cwmp__IGD_LANDevice,
								 sel[2],
								 cwmp__IGD_LANDev_i_LANHostConfigManagement,
								 cwmp__IGD_LANDev_i_HostCfgMgt_AllowedMACAddresses, 0 });

	buf = malloc(8192);
	if (!buf)
		return;

	memset(buf, 0, 8192);
	mac_list = (struct maclist *) buf;
	addr = mac_list->ea;

	/* FIXME: foreach is insane */
	foreach(wbuf, v, next) {
		if (ether_atoe(wbuf, addr->ether_addr_octet)) {
			mac_list->count++;
			addr++;
		}
	}

	bcom_ioctl(ifname, WLC_SET_MACLIST, buf, 8192);
	free(buf);

}

#if 0
static unsigned int brcm43xxwl_auto_channel(char *device)
{
        int chosen = 0;
        wl_uint32_list_t request;
        int phytype;
        int ret;
        int i;

        /* query the phy type */
        bcom_get_int(device, WLC_GET_PHYTYPE, &phytype);

        request.count = 0;      /* let the ioctl decide */
        bcom_ioctl(device, WLC_START_CHANNEL_SEL, &request, sizeof(request));
        if (!ret) {
                sleep_ms(phytype == WLC_PHY_TYPE_A ? 1000 : 750);
                for (i = 0; i < 100; i++) {
                        bcom_get_int(device, WLC_GET_CHANNEL_SEL, &chosen);
                        if (!ret)
                                break;
                        sleep_ms(100);
                }
        }
        debug("interface %s: channel selected %d\n", device, chosen);
        return chosen;
}
#endif

struct vif_desc {
	tr069_selector *sel;
	struct tr069_value_table *ift;
};

int brcm43xxwl_ifup(const char *device, struct tr069_value_table *st)
{
	ENTER();

	int opmode;
	int rc, val;

	int i, ap, sta, wet, wds, apsta;

	/* FIXME: nvram stuff */
	prefix = device;

	struct vif_desc iface[16];
	int ifaces = 0;

	if (!st) {
		EXIT();
		return -1;
	}

	for (i = 0; i < st->size; i++) {
		struct tr069_value_table *d;
		tr069_selector *sel;
		struct tr069_value_table *ift;

		d = tr069_get_table_by_index(st, i);
		debug("Device: %d, %p\n", i, d);
		if (!d)
			continue;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
		sel = tr069_get_selector_by_id(d, cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
		debug("Selector: %p\n", sel);
		if (!sel)
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration */
		if ((*sel)[1] != cwmp__IGD_LANDevice ||
		    (*sel)[2] == 0 ||
		    (*sel)[3] != cwmp__IGD_LANDev_i_WLANConfiguration ||
		    (*sel)[4] == 0)
			continue;

		ift = tr069_get_table_by_selector(*sel);
		if (!ift)
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Enable */
		if (!tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_WLANCfg_j_Enable))
			continue;

		iface[ifaces].sel = sel;
		iface[ifaces].ift = ift;
		ifaces++;
		debug(": ifaces: %d\n", ifaces);
	}

	init_ctrl_socket();

	stop_bcom(device);

	if (bcom_ioctl(device, WLC_GET_MAGIC, &val, sizeof(val)) < 0) {
		EXIT();
		return -1;
	}

	/* Clear all VIFs */
	for (i = 0; i < 16; i++) {
		int cfg[2]; /* index, enabled */

		cfg[0] = i;
		cfg[1] = 0;

		bcom_set_var(device, "bss", cfg, sizeof(cfg));
	}

	if (!ifaces) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.DeviceOperationMode */
	opmode = tr069_get_enum_by_id(iface[0].ift, cwmp__IGD_LANDev_i_WLANCfg_j_DeviceOperationMode);
	rc = -1;
	ap = sta = wet = wds = 0;

	switch (opmode) {
		/* InfrastructureAccessPoint */
		case 0:
			ap = 1;
			break;

		/* WirelessBridge */
		case 1:
			wds = 1;
			break;

		/* WirelessRepeater */
		case 2:
			wet = 1;
			break;

		/* WirelessStation */
		case 3:
			sta = 1;
			break;
	}

	debug("AP: %d, WDS: %d, WET: %d, STA: %d\n", ap, wds, wet, sta);

	bcom_set_int_var(device, "mssid", (ifaces > 1 || ap || wds));

	bcom_set_int(device, WLC_SET_AP, (ap || wds));

        /* Set mode: WET */
        if (wet)
                bcom_set_int(device, WLC_SET_WET, wet);

	apsta = (sta && ifaces > 1);
	bcom_set_int_var(device, "apsta", apsta);

        bcom_set_int(device, WLC_SET_INFRA, 1);

	setup_bcom_common(device, iface[0].ift);
	if (wds)
		setup_bcom_wds(device, iface[0].ift);

	if (ap || wds)
		/* allow lazywds on all AP's */
		bcom_set_int(device, WLC_SET_LAZYWDS, 1);

	/* FIXME: no afterburner for now */
	bcom_set_int_var(device, "afterburner_override", 0);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.MACAddressControlEnabled */
	if (tr069_get_bool_by_id(iface[0].ift, cwmp__IGD_LANDev_i_WLANCfg_j_MACAddressControlEnabled)) {
		setup_bcom_mac_acl(device, *iface[0].sel);
		bcom_set_int(device, WLC_SET_MACMODE, WLC_MACMODE_ALLOW);
	} else
		bcom_set_int(device, WLC_SET_MACMODE, WLC_MACMODE_DISABLED);

	setup_bcom_gmode(device, iface[0].ift);

	for (i = 0; i < ifaces; i++)
		setup_bcom_vif(device, i, iface[i].ift);

	start_bcom(device);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.X_TPOSS_TxPower */
	val = mw_to_qdbm(tr069_get_uint_by_id(iface[0].ift, cwmp__IGD_LANDev_i_WLANCfg_j_X_TPOSS_TxPower));
	bcom_set_int_var(device, "qtxpower", val);

	if (ap) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.WLANConfiguration.{i}.Channel */
		val = tr069_get_uint_by_id(iface[0].ift, cwmp__IGD_LANDev_i_WLANCfg_j_Channel);
		if (!val) {
			bcom_set_int(device, WLC_SET_CHANNEL, val);

			/* set the auto channel scan timer in the driver when in auto mode */
			val = 15;
		} else
			/* reset the channel scan timer in the driver when not in auto mode */
			val = 0;
		bcom_set_int(device, WLC_SET_CS_SCAN_TIMER, val);
	}

	for (i = 0; i < ifaces; i++) {
		/* the interface is ready to go, add it to it's lan bridge */
		tr069_selector if_sel;

		tr069_selcpy(if_sel, *iface[i].sel);
		if_sel[3] = 0;
		if_add2LANdevice(device, if_sel);
	}

	if (ap || wds || wet) {
		for (i = 0; i < ifaces; i++) {
			setup_bcom_vif_sec(device, i, iface[i].ift);
		}

		for (i = 0; i < ifaces; i++) {
			start_bcom_vif(device, i, iface[i].ift);
		}
	}

	if (sta || wet)
		start_watchdog(device, *iface[0].sel);



	for (i = 0; i < ifaces; i++) {
		/* setup the static routes through this interface */
		if_routes(device, *iface[i].sel);
	}

	EXIT();
	return 0;
}

int brcm43xxwl_wdsup(const char *device)
{
	char *s;
	char dev[16];
	char wldev[16];
	int major;
	int minor;
	int r;

	ENTER();

	strncpy(dev, device, sizeof(dev));
	for (s = dev; *s && !isdigit(*s); s++)
		;

	if (!*s) {
		EXIT();
		return -1;
	}

	r = sscanf(s, "%d.%d", &major, &minor);
	if (r != 2) {
		EXIT();
		return -1;
	}

	*s = '\0';

	snprintf(wldev, sizeof(wldev), "wl%d", major);

	struct tr069_value_table *st;
	st = get_if_layout(wldev);

	if (!st) {
		EXIT();
		return -1;
	}

	for (int i = 0; i < st->size; i++) {
		struct tr069_value_table *d;
		tr069_selector           *sel;

		d = tr069_get_table_by_index(st, i);
		debug("Device: %d, %p\n", i, d);
		if (!d)
			continue;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
		sel = tr069_get_selector_by_id(d, cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
		if (!sel)
			continue;

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice */
		if ((*sel)[1] == cwmp__IGD_LANDevice ||
		    (*sel)[2] != 0 ||
		    (*sel)[3] == cwmp__IGD_LANDev_i_WLANConfiguration ||
		    (*sel)[4] != 0) {

			/*
			 * found it
			 */

			/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Device */
			if_add2ifmap(device, *sel);

			/* the interface is ready to go, add it to it's lan bridge */
			tr069_selector if_sel;

			tr069_selcpy(if_sel, *sel);
			if_sel[3] = 0;
			if_add2LANdevice(device, if_sel);

			break;
		}
	}

	EXIT();
	return 0;
}
