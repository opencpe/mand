/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004,2006 Andreas Schultz <as@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/ioctl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <net/if.h>
#include <pwd.h>
#include "list.h"

#include "tr069.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#define SDEBUG
#include "debug.h"
#include "utils/logx.h"
#include "process.h"
#include "ifup.h"
#include "lng.h"
#include "l3forward.h"
#include "proxy.h"
#include "snmpd.h"
#include "inet_helper.h"
#include "if_madwifi.h"
#include "radius.h"
#include "dhcp.h"
#include "firewall.h"
//#include "ppp_server.h"

#define ereturn(format, ...) { logx(LOG_ERR, format, ## __VA_ARGS__); EXIT(); return -1; }

#define IFC_NONE       0

#define IFC_ETH        1                      /* raw ethernet interface */
#define IFC_WLAN       2                      /* wifi interface */
#define IFC_USB        3
#define IFC_ATM        4                      /* atm (dsl) line interface */

#define IFC_WAN        5                      /* used for wan */
#define IFC_LAN        6                      /* used for lan */
#define IFC_BR_SLAVE   7                      /* used for lan */
#define IFC_ATHEROS    8                      /* used for atheros */
#define IFC_TIAP       9                      /* used for TIAP */
#define IFC_BR        10
#define IFC_ATH_VAP   11                      /* used for atheros */
#define IFC_BR2684    12                      /* ATM bridged interface */
#define IFC_DSL       13

#define IFC_F_SWITCH   (1 << 0)

enum { ifc_Ethernet	= cwmp___IGD_IfMap_IfType_i_Type_Ethernet,
       ifc_Atheros	= cwmp___IGD_IfMap_IfType_i_Type_Atheros,
       ifc_AtherosVAP	= cwmp___IGD_IfMap_IfType_i_Type_VirtualAP,
       ifc_Layer2Bridge	= cwmp___IGD_IfMap_IfType_i_Type_Layer2Bridge,
       ifc_ATMBridge	= cwmp___IGD_IfMap_IfType_i_Type_ATMBridge,
       ifc_ATM		= cwmp___IGD_IfMap_IfType_i_Type_ATM,
       ifc_ADSL		= cwmp___IGD_IfMap_IfType_i_Type_ADSL,
       ifc_PPP		= cwmp___IGD_IfMap_IfType_i_Type_PPP,
       ifc_VLAN		= cwmp___IGD_IfMap_IfType_i_Type_VLAN,
       ifc_BRCM43xxWL	= cwmp___IGD_IfMap_IfType_i_Type_BroadcomWL,
       ifc_BroadcomWDS	= cwmp___IGD_IfMap_IfType_i_Type_BroadcomWDS,
       ifc_IPoA		= cwmp___IGD_IfMap_IfType_i_Type_IPoA,
       ifc_OFSwitch	= cwmp___IGD_IfMap_IfType_i_Type_OFSwitch,
};

static int wan_ipup(const char *device, const char *link);

static struct tr069_instance *if_map;
static struct tr069_instance *if_instances;

static int ntpd_running = 0;
static int hs_id;
static int dnsmasq_id;
pthread_rwlock_t tr069_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static pthread_mutex_t system_up_mutex = PTHREAD_MUTEX_INITIALIZER;
static int is_system_up = 0;

int dnsmasq_config(void);
void init_hw_defaults(const char *dev);

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}

static tr069_selector *wan_get_cic_conn(const tr069_selector sel);

static int get_if_type(const char *if_name)
{
	int l, n;
	int ret = -1;
	static const char vl[] = "vlan";
	struct tr069_instance_node *node;

	if (!if_map)
		return 0;

	for (l = 0; if_name[l] && !isdigit(if_name[l]); l++);
	for (n = l; if_name[n] && isdigit(if_name[n]); n++);

	if(if_name[n] == '.') {
		if_name = vl;
		l = strlen(vl);
		debug(": This appears to be a VLAN, setting if_name to %s.", if_name);
	}

	if (!l)
		return 0;

	pthread_rwlock_rdlock(&tr069_rwlock);
	for (node = tr069_instance_first(if_map);
	     node != NULL;
	     node = tr069_instance_next(if_map, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType.{i} */

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType.{i}.Name */
		const char *s = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_IfType_i_Name);
		if (strncasecmp(s, if_name, l) == 0) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType.{i}.Type */
			ret = tr069_get_enum_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_IfType_i_Type);
			break;
		}
	}
	pthread_rwlock_unlock(&tr069_rwlock);

	return ret;
}

struct tr069_instance *get_if_layout(const char *if_name)
{
	struct tr069_instance *ret = NULL;
	struct tr069_instance_node *node;

	if (!if_instances)
		return NULL;

	pthread_rwlock_rdlock(&tr069_rwlock);
	for (node = tr069_instance_first(if_instances);
	     node != NULL;
	     node = tr069_instance_next(if_instances, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
		if (strcasecmp(tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_If_i_Name), if_name) == 0) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device */
			ret = tr069_get_instance_ref_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_If_i_Device);
			break;
		}
	}
	pthread_rwlock_unlock(&tr069_rwlock);

	return ret;
}

const struct tr069_instance_node *get_interface_node_by_name(const char *if_name)
{
	struct tr069_instance_node *node;

	ENTER();

	if (!if_instances)
		return NULL;

	pthread_rwlock_wrlock(&tr069_rwlock);
        for (node = tr069_instance_first(if_instances);
             node != NULL;
             node = tr069_instance_next(if_instances, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
		if (!(strcasecmp(tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_If_i_Name), if_name)))
			goto out;
	}

	node = NULL;
out:
	pthread_rwlock_unlock(&tr069_rwlock);

	EXIT();
	return node;
}

const struct tr069_instance_node *get_interface_node_by_selector(const tr069_selector sel)
{
	struct tr069_instance_node *node;

	ENTER();

	if (!if_instances || !sel)
		return NULL;

	pthread_rwlock_rdlock(&tr069_rwlock);
	for (node = tr069_instance_first(if_instances);
	     node != NULL;
	     node = tr069_instance_next(if_instances, node)) {
		struct tr069_instance *if_dref;
		struct tr069_instance_node *if_node;
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device */
		if_dref = tr069_get_instance_ref_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_If_i_Device);
		if (!if_dref)
			continue;

		for (if_node = tr069_instance_first(if_dref);
		     if_node != NULL;
		     if_node = tr069_instance_next(if_dref, if_node)) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */
			tr069_selector *d_sel;

			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
			d_sel = tr069_get_selector_by_id(DM_TABLE(if_node->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
			if (!d_sel)
				continue;

			if (!(tr069_selcmp(*d_sel, sel, TR069_SELECTOR_LEN)))
				/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */
				goto out;
		}
	}
	node = NULL;
out:
	pthread_rwlock_unlock(&tr069_rwlock);

	EXIT();
	return node;

}

const char *get_if_device(const tr069_selector sel)
{
	const struct tr069_instance_node *node;

	if (!sel)
		return NULL;

	node = get_interface_node_by_selector(sel);
	if(node)
		return tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_If_i_Name);

	return NULL;
}

static const char ppp0_device[] = "ppp0";

const tr069_selector *get_wan_device_sel(int id)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	/** VAR: InternetGatewayDevice.WANDevice,{i}.WANConnectionDevice.1 */
	tr069_selector sel = {cwmp__InternetGatewayDevice,
			      cwmp__IGD_WANDevice,
			      id,
			      cwmp__IGD_WANDev_i_WANConnectionDevice,
			      1, 0 };

	debug(": lockup: %s", sel2str(b1, sel));
	return wan_get_cic_conn(sel);
}

struct in_addr get_wan_ip(int id)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	const tr069_selector *ccc;
	tr069_selector sel;
	struct in_addr ret = { .s_addr = INADDR_NONE};

	ENTER();

	ccc = get_wan_device_sel(id);
	if (!ccc) {
		EXIT();
		return ret;
	}
	tr069_selcpy(sel, *ccc);

	if (sel[5] == cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection) {
		/** VAR: InternetGatewayDevice.WANDevice,{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.ExternalIPAddress */
		sel[7] = cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_ExternalIPAddress;
	} else if (sel[5] == cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection) {
		/** VAR: InternetGatewayDevice.WANDevice,{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.ExternalPPPAddress */
		sel[7] = cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_ExternalIPAddress;
	} else {
		EXIT();
		return ret;
	}

	sel[8] = 0;
	debug(": lockup: %s", sel2str(b1, sel));
	ret = tr069_get_ipv4_by_selector(sel);

	EXIT();
	return ret;
}

const char *get_wan_device(int id)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const char *wan = NULL;
	tr069_selector *ccc;

	/** VAR: InternetGatewayDevice.WANDevice,{i}.WANConnectionDevice.1 */
	tr069_selector sel = {cwmp__InternetGatewayDevice,
			      cwmp__IGD_WANDevice,
			      id,
			      cwmp__IGD_WANDev_i_WANConnectionDevice,
			      1, 0 };

	debug(": lockup: %s", sel2str(b1, sel));
	ccc = wan_get_cic_conn(sel);
	if (ccc) {
		debug(": got ccc: %s", sel2str(b1, *ccc));
		wan = get_if_device(*ccc);
	}
	if (ccc && !wan && (*ccc)[5] == cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection) {
		debug(": ccc && !wan && ppp_dev");
		wan = ppp0_device;
	}

	if (!wan) {
		wan = get_if_device(sel);
		debug(": direct lockup: %s -> %s", sel2str(b1, sel), wan);
	}

	return wan;
}

int get_wan_nat(int id)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	const tr069_selector *ccc;
	tr069_selector sel;
	int ret = 0;

	ENTER();

	ccc = get_wan_device_sel(id);
	if (!ccc) {
		EXIT();
		return ret;
	}
	tr069_selcpy(sel, *ccc);

	switch (sel[5]) {
	case cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection:
		/** VAR: InternetGatewayDevice.WANDevice,{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.NATEnabled */
		sel[7] = cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_NATEnabled;
		break;

	case cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection:
		/** VAR: InternetGatewayDevice.WANDevice,{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.NATEnabled */
		sel[7] = cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_NATEnabled;
		break;

	default:
		EXIT();
		return ret;
	}

	sel[8] = 0;
	debug(": lockup: %s", sel2str(b1, sel));
	ret = tr069_get_bool_by_selector(sel);

	EXIT();
	return ret;
}

/* Strip trailing CR/NL from string <s> */
#define chomp(s) ({ \
        char *c = (s) + strlen((s)) - 1; \
        while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
                *c-- = '\0'; \
        s; \
})

void if_linkup(const char *iface)
{
	ENTER();
	do_ethflags(iface, IFF_UP, IFF_UP);

	if (iface && strcmp(iface, "eth0") == 0) {
		debug(": hw_defaults");
		init_hw_defaults(iface);
	}

	EXIT();
}

void if_linkdown(const char *iface)
{
	ENTER();
	do_ethflags(iface, ~IFF_UP, IFF_UP);
}

static void if_ipup(const char *iface, struct in_addr ipaddr, struct in_addr netmask)
{
	struct in_addr bcast;
	int plen;
	char ipaddr_buf[INET_ADDRSTRLEN];
	char bcast_buf[INET_ADDRSTRLEN];

	plen = 33 - ffs(ntohl(netmask.s_addr));
	bcast.s_addr = ipaddr.s_addr | ~netmask.s_addr;

	vasystem("ip addr add %s/%d broadcast %s dev %s",
		 inet_ntop(AF_INET, &ipaddr, ipaddr_buf, INET_ADDRSTRLEN), plen,
		 inet_ntop(AF_INET, &bcast, bcast_buf, INET_ADDRSTRLEN), iface);
}

static void if_ipdown(const char *iface)
{
	vasystem("ip addr flush dev %s", iface);
}


void start_udhcpc(const char *iface)
{
	char pid_file[256];
	char vendor[256];
	const char *argv[] = { UDHCPC, "-p", pid_file, "-i", iface, "-V", vendor, "-O", "staticroutes", "-h", NULL, NULL };

        /** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_FQHostname */
        argv[10] = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
                                cwmp__IGD_DeviceInfo,
                                cwmp__IGD_DevInf_X_TPLINO_FQHostname, 0 });
        if (!argv[10])
                argv[10] ="TPLINO";

	snprintf(vendor, sizeof(vendor), "%s-%s",
		 tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
					 cwmp__IGD_DeviceInfo,
					 cwmp__IGD_DevInf_HardwareVersion, 0 }),
		 tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
					 cwmp__IGD_DeviceInfo,
					 cwmp__IGD_DevInf_SoftwareVersion, 0 }));

	snprintf(pid_file, sizeof(pid_file), PID_DIR "/udhcpc.%s.pid", iface);
	daemonize(argv);
}

int stop_udhcpc(const char *iface)
{
	struct stat filestat;
	char pid_file[256];

	snprintf(pid_file, sizeof(pid_file), PID_DIR "/udhcpc.%s.pid", iface);

	if (stat(pid_file, &filestat))
		return -1;

	killpidfile(pid_file);
	unlink(pid_file);

	return 0;
}

int signal_udhcpc(const char *iface, int signal)
{
	struct stat filestat;
	char pid_file[256];

	snprintf(pid_file, sizeof(pid_file), PID_DIR "/udhcpc.%s.pid", iface);

	if (stat(pid_file, &filestat))
		return -1;

	signalpidfile(pid_file, signal);

	return 0;
}

static void start_dnsmasq(void)
{
	const char *const argv[] = {DNSMASQ, "-C", DNSMASQ_CONF, "-k", "-x", PID_DIR "/dnsmasq.pid", NULL};

	dnsmasq_id = supervise(argv);
}

static void stop_dnsmasq(void)
{
	kill_supervise(dnsmasq_id, SIGTERM);
}

static inline void luci_config(void)
{
	ENTER();

	/* create luci config file */
	/* FIXME: this doesn't have to be written by the device manager... */
	FILE *cfg_file_luci = fopen(LUCI_CFG, "w+");
	if (!cfg_file_luci) {
		EXIT();
		return;
	}

	fprintf(cfg_file_luci, "config %s %s\n", "core", "main");
	fprintf(cfg_file_luci, "  option %s %s\n", "lang", "auto");
	fprintf(cfg_file_luci, "  option %s %s\n", "mediaurlbase", "/luci-static/openwrt.org");
	fprintf(cfg_file_luci, "  option %s %s\n\n", "resourcebase", "/luci-static/resources");

	fprintf(cfg_file_luci, "config %s %s\n", "extern", "flash_keep");
	fprintf(cfg_file_luci, "  option %s %s\n", "uci", "'/etc/config/'");
	fprintf(cfg_file_luci, "  option %s %s\n", "dropbear", "'/etc/dropbear/'");
	fprintf(cfg_file_luci, "  option %s %s\n", "openvpn",	"'/etc/openvpn/'");
	fprintf(cfg_file_luci, "  option %s %s\n", "passwd", "'/etc/passwd'");
	fprintf(cfg_file_luci, "  option %s %s\n", "opkg", "'/etc/opkg.conf'");
	fprintf(cfg_file_luci, "  option %s %s\n", "firewall", "'/etc/firewall.user'");
	fprintf(cfg_file_luci, "  option %s %s\n\n", "uploads", "'/lib/uci/upload/'");

	fprintf(cfg_file_luci, "config %s %s\n\n", "internal", "languages");

	fprintf(cfg_file_luci, "config %s %s\n", "internal", "sauth");
	fprintf(cfg_file_luci, "  option %s %s\n", "sessionpath", "'/tmp/luci-sessions'");
	fprintf(cfg_file_luci, "  option %s %s\n\n", "sessiontime", "3600");

	fprintf(cfg_file_luci, "config %s %s\n", "internal", "ccache");
	fprintf(cfg_file_luci, "  option %s %s\n\n", "enable", "1");

	fprintf(cfg_file_luci, "config %s %s\n", "internal", "template");
	fprintf(cfg_file_luci, "  option %s %s\n", "compiler_mode", "file");
	fprintf(cfg_file_luci, "  option %s %s\n\n", "compiledir", "'/tmp/luci-templatecache'");

	fprintf(cfg_file_luci, "config %s %s\n", "internal", "themes");

	fclose(cfg_file_luci);

	EXIT();
}

static pthread_mutex_t httpd_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct httpd_info_t httpd_info_head = {
	.next = NULL
};

static int httpd_config_ipint(FILE *file, int ifsel_len,
			      struct tr069_instance_node *node,
			      tr069_id enable, tr069_selector address)
{
	char		buffer[MAX_PARAM_NAME_LEN];
	char		*path;

	struct in_addr	ipaddr;
	char		ip_buffer[INET_ADDRSTRLEN];

	if (!tr069_get_bool_by_id(DM_TABLE(node->table), enable))
		return 0;

			/* tr069_get_ipv4_by_id cannot be used since the
			   parameter may have a function to dynamically retrieve the IP */
	ipaddr = tr069_get_ipv4_by_selector(address);
	if (ipaddr.s_addr == INADDR_ANY || ipaddr.s_addr == INADDR_BROADCAST)
		return 0;

	/* terminate interface selector (contained in IPAddress selector) */
	address[ifsel_len] = 0;
	if (!(path = tr069_sel2name(address, buffer, sizeof(buffer))))
		return 0;

	inet_ntop(AF_INET, &ipaddr, ip_buffer, INET_ADDRSTRLEN);
			/*
			 * FIXME: interface selector is appended to the IP for each list entry
			 * this is currently the easiest way to pass the selector since there are
			 * no sub-sections in UCI
			 */
	fprintf(file, "  list %s \"%s %s\"\n", "ip", ip_buffer, path);

	return 1;
}

		/* this is ok currently but if deleting an instance recreating it
		   with the same server Id has to be supported, we need to do
		   a (slower) strcmp with the server Id */
static inline int httpd_cmp(struct httpd_info_t *item, tr069_id needle)
{
	return INTCMP(item->inst, needle);
}

static void httpd_reload(void)
{
	FILE *cfg_file;
	struct tr069_instance *http_inst;

	ENTER();

	if (!test_system_up()) {
		debug(": called before 'system up' was received");
		EXIT();
		return;
	}

	pthread_mutex_lock(&httpd_mutex);

	/* create lucittpd config file */
	cfg_file = fopen(LUCITTPD_CFG, "w+");
	if (!cfg_file) {
		pthread_mutex_unlock(&httpd_mutex);
		EXIT();
		return;
	}

	/* FIXME: use libuci to write UCI config files */
	fprintf(cfg_file, "config %s %s\n", "lucittpd",  "lucittpd");
	fprintf(cfg_file, "  option %s %s\n", "timeout", "90");
	fprintf(cfg_file, "  option %s %s\n", "keepalive", "0");
	fprintf(cfg_file, "  option %s %s\n", "path", "/usr/lib/lucittpd/plugins/");
	fprintf(cfg_file, "  option %s %s\n", "root", "/www/");

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer */
	http_inst = tr069_get_instance_ref_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
									cwmp__IGD_X_TPLINO_NET_HTTPServers,
									cwmp__IGD_HTTPSrvs_HTTPServer, 0});
	if (!http_inst) {
		fclose(cfg_file);
		pthread_mutex_unlock(&httpd_mutex);
		EXIT();
		return;
	}

	/*
	 *	HTTP Server Instances
	 */
	for (struct tr069_instance_node *server_node = tr069_instance_first(http_inst);
	     server_node; server_node = tr069_instance_next(http_inst, server_node)) {
		struct tr069_value_table *http_table = DM_TABLE(server_node->table);

		unsigned int port_value;
		const char *serverId;
		int HTTPsEnabled;

		int cfgValid = 0;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer.{i}.Enabled */
		if (!tr069_get_bool_by_id(http_table, cwmp__IGD_HTTPSrvs_HTTPSrv_i_Enabled))
			continue;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer.{i}.HTTPServerId */
		serverId = tr069_get_string_by_id(http_table, cwmp__IGD_HTTPSrvs_HTTPSrv_i_HTTPServerId);
		if (!serverId) {
			fclose(cfg_file);
			pthread_mutex_unlock(&httpd_mutex);
			EXIT();
			return;
		}

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer.{i}.Port */
		port_value = tr069_get_uint_by_id(http_table, cwmp__IGD_HTTPSrvs_HTTPSrv_i_Port);

		fprintf(cfg_file, "\nconfig %s %s\n", "HTTPServer", serverId);
		fprintf(cfg_file, "  option %s %i\n", "port", port_value);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer.{i}.HTTPsEnabled */
		HTTPsEnabled = tr069_get_bool_by_id(http_table, cwmp__IGD_HTTPSrvs_HTTPSrv_i_HTTPsEnabled);
		if (HTTPsEnabled) {
			fprintf(cfg_file, "  option %s %s\n", "type", "https");
			fprintf(cfg_file, "  option %s %s\n", "ssl_key", LUCITTPD_SSL_KEY);
			fprintf(cfg_file, "  option %s %s\n", "ssl_crt", LUCITTPD_SSL_CRT);
			fprintf(cfg_file, "  option %s %s\n", "ssl_ca", LUCITTPD_SSL_CA);
		} else {
			fprintf(cfg_file, "  option %s %s\n", "type", "http");
		}

		if (HTTPsEnabled &&
		    (access(LUCITTPD_SSL_KEY, R_OK) ||
		     access(LUCITTPD_SSL_CRT, R_OK) ||
		     access(LUCITTPD_SSL_CA, R_OK)))
		     	continue; /* ok since currently we can't ensure there are keys/certs */

		struct tr069_instance *assocDev_inst;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer.{i}.AssociatedDevice. */
		assocDev_inst = tr069_get_instance_ref_by_id(http_table, cwmp__IGD_HTTPSrvs_HTTPSrv_i_AssociatedDevice);
		if (!assocDev_inst) {
			fclose(cfg_file);
			pthread_mutex_unlock(&httpd_mutex);
			EXIT();
			return;
		}

		/*
		 *	associated Device Instances
		 */
		for (struct tr069_instance_node *assocDev_node = tr069_instance_first(assocDev_inst);
		     assocDev_node; assocDev_node = tr069_instance_next(assocDev_inst, assocDev_node)) {
			struct tr069_value_table *assocDev_table = DM_TABLE(assocDev_node->table);

			tr069_selector *sel_assocDev;

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.HTTPServer.{i}.AssociatedDevice.{i}.DeviceReference */
			sel_assocDev = tr069_get_selector_by_id(assocDev_table, cwmp__IGD_HTTPSrvs_HTTPSrv_i_AssocDvc_j_DeviceReference);
			if (!sel_assocDev) {
				fclose(cfg_file);
				pthread_mutex_unlock(&httpd_mutex);
				EXIT();
				return;
			}

			/** VAR: InternetGatewayDevice.LANDevice.{i} */
			if ((*sel_assocDev)[1] == cwmp__IGD_LANDevice) {
				/* distinction whether Ip or device */
				if ((*sel_assocDev)[3] == cwmp__IGD_LANDev_i_LANHostConfigManagement) {
					tr069_selector sel;

					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i} */
					struct tr069_instance_node *instance_node = tr069_get_instance_node_by_selector(*sel_assocDev);
					if (!instance_node) {
						fclose(cfg_file);
						pthread_mutex_unlock(&httpd_mutex);
						EXIT();
						return;
					}

					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceIPAddress */
					tr069_selcpy(sel, *sel_assocDev);
					sel[6] = cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceIPAddress;
					sel[7] = 0;

					cfgValid |= httpd_config_ipint(cfg_file, 3, instance_node,
								       cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_Enable, sel);
				} else {
					struct tr069_instance *ipint_inst;
					tr069_selector sel;

					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface */
					tr069_selcpy(sel, *sel_assocDev);
					sel[3] = cwmp__IGD_LANDev_i_LANHostConfigManagement;
					sel[4] = cwmp__IGD_LANDev_i_HostCfgMgt_IPInterface;
					sel[5] = 0;

					ipint_inst = tr069_get_instance_ref_by_selector(sel);
					if (!ipint_inst)
						continue; /* ok here since the default/upgrade server cfg will likely result
							     in associated devices with no IP If */

					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceIPAddress */
					/* sel[5] will be the instance id */
					sel[6] = cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceIPAddress;
					sel[7] = 0;

					for (struct tr069_instance_node *node = tr069_instance_first(ipint_inst);
					     node; node = tr069_instance_next(ipint_inst, node)) {
						sel[5] = node->instance;
						cfgValid |= httpd_config_ipint(cfg_file, 3, node,
									       cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_Enable, sel);
					}
				}
			} else if ((*sel_assocDev)[1] == cwmp__IGD_WANDevice) {
				/* distinction whether Ip or device */
				if ((*sel_assocDev)[5] == cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection) {
					tr069_selector sel;

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i} */
					struct tr069_instance_node *instance_node = tr069_get_instance_node_by_selector(*sel_assocDev);
					if (!instance_node) {
						fclose(cfg_file);
						pthread_mutex_unlock(&httpd_mutex);
						EXIT();
						return;
					}

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.ExternalIPAddress */
					tr069_selcpy(sel, *sel_assocDev);
					sel[7] = cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_ExternalIPAddress;
					sel[8] = 0;

					cfgValid |= httpd_config_ipint(cfg_file, 5, instance_node,
								       cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_Enable, sel);
				} else {
					struct tr069_instance *ipint_inst;
					tr069_selector sel;

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection */
					tr069_selcpy(sel, *sel_assocDev);
					sel[5] = cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection;
					sel[6] = 0;

					ipint_inst = tr069_get_instance_ref_by_selector(sel);
					if (!ipint_inst)
						continue; /* see above */

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.ExternalIPAddress */
					/* sel[6] will be the instance id */
					sel[7] = cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_ExternalIPAddress;
					sel[8] = 0;

					for (struct tr069_instance_node *node = tr069_instance_first(ipint_inst);
					     node; node = tr069_instance_next(ipint_inst, node)) {
						sel[6] = node->instance;
						cfgValid |= httpd_config_ipint(cfg_file, 5, node,
									       cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_Enable, sel);
					}
				}
			}
		}

		if (cfgValid) {
			struct httpd_info_t *p;

			list_search(struct httpd_info_t, httpd_info_head, server_node->instance, httpd_cmp, p);

			if (p) {
				p->state = HTTPD_STATE_INFORM;
			} else {
				p = malloc(sizeof(struct httpd_info_t));
				if (!p) {
					fclose(cfg_file);
					pthread_mutex_unlock(&httpd_mutex);
					EXIT();
					return;
				}
				p->state = HTTPD_STATE_START;
				p->inst = server_node->instance;
				p->server_id = serverId;

				list_append(struct httpd_info_t, httpd_info_head, p);
			}
		} /* otherwise it remains HTTPD_STATE_STARTED and has to be terminated,
		     or doesn't exist in the list and doesn't have to be started
		     (of course this also applies to previous 'continues') */
	}

	fclose(cfg_file);

		/* FIXME: following could be put into a separate function, but keep in
		   mind that the critical section covers BOTH functions */

	struct httpd_info_t *p, *n;
	list_foreach_safe(struct httpd_info_t, httpd_info_head, p, n)
		switch (p->state) {
		case HTTPD_STATE_START: {
			char *argv[] = {LUCITTPD, p->server_id, NULL};

			if (!(p->id = supervise(argv))) {
				pthread_mutex_unlock(&httpd_mutex);
				EXIT();
				return;
			}

			p->state = HTTPD_STATE_STARTED;
			break;
		}

		case HTTPD_STATE_STARTED: /* was already in list and has to be terminated */
			kill_supervise(p->id, SIGTERM);
			list_remove(struct httpd_info_t, httpd_info_head, p);
			free(p);
			break;

		case HTTPD_STATE_INFORM:
			signal_supervise(p->id, SIGUSR1);
			p->state = HTTPD_STATE_STARTED;
			break;
		}

	pthread_mutex_unlock(&httpd_mutex);
	EXIT();
}

/* keep them separated for now, in case we wan't to revert */

void dm_httpd_restart_action(const tr069_selector sel __attribute__((unused)),
			     enum dm_action_type type __attribute__((unused)))
{
	httpd_reload();
}

void dm_httpd_reload_action(const tr069_selector sel __attribute__((unused)),
			    enum dm_action_type type __attribute__((unused)))
{
	httpd_reload();
}

static void start_wan_ntpd(void)
{
	const char *argv[] = {NTPD, "-g", "-c", NTPD_CFG, NULL};
	const char *s[5];
	int i,run_ntpd = 0;
	FILE *fout;
	struct tr069_value_table *t;

	t = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice, cwmp__IGD_Time, 0});

	for (i = 0; i < 5; i++) {
		/** VAR: InternetGatewayDevice.Time.NTPServerX */
		s[i] = tr069_get_string_by_id(t, cwmp__IGD_Time_NTPServer1 + i);
		run_ntpd |= (s[i] && *s[i]);
	}

	if (!run_ntpd)
		return;

	fout = fopen(NTPD_CFG, "w");
	if (!fout)
		return;

	fprintf(fout, "restrict 127.0.0.1\n");
	fprintf(fout, "driftfile /var/lib/ntp/ntp.drift\n");

	for (i = 0; i < 5; i++)
		if (s[i] && *s[i])
			fprintf(fout, "server %s iburst\n", s[i]);

	fclose(fout);

	mkdir("/var/lib", 0755);
	mkdir("/var/lib/ntp", 0755);

	start_daemon(argv);
	ntpd_running = 1;
}

static void stop_wan_ntpd(void)
{
	vsystem("killall ntpd");
	ntpd_running = 0;
}

void dm_check_ntpd_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	stop_wan_ntpd();
	start_wan_ntpd();
}

static int syslog_config(void)
{
	static int firstrun = 1;
	struct in_addr addr;
	char ipaddr[INET_ADDRSTRLEN];

	/** VAR: InternetGatewayDevice.DeviceInfo.SyslogServer */
	addr = tr069_get_ipv4_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							    cwmp__IGD_DeviceInfo,
							    cwmp__IGD_DevInf_SyslogServer, 0});

	vsystem("killall -9 syslogd");

	logx_remote(addr);

	if (firstrun)
		vsystem("logread > /var/log/boot.msg");

	if (addr.s_addr == INADDR_ANY || addr.s_addr == INADDR_NONE){
		vsystem("/sbin/syslogd -C512");
	} else {
		inet_ntop(AF_INET, &addr, ipaddr, INET_ADDRSTRLEN);
		vasystem("/sbin/syslogd -C512 -L -R %s", ipaddr);
	}
	firstrun = 0;
	return 1;
}


void dm_restart_syslog_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	syslog_config();

#if 0 /* proxyd currently unusable */
	/* Reload would not have been sufficient, since syslog ip is a command line option.
	   Reload only triggers a new config to be read. */
	stop_proxy();
	start_proxy();
#endif
}

static int hosts_file(void)
{
	FILE *fout;
	struct in_addr addr;
	char ipaddr[INET_ADDRSTRLEN];

	/** VAR: InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.IPInterfaceIPAddress */
	addr = tr069_get_ipv4_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							    cwmp__IGD_LANDevice,
							    1,
							    cwmp__IGD_LANDev_i_LANHostConfigManagement,
							    cwmp__IGD_LANDev_i_HostCfgMgt_IPInterface,
							    1,
							    cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceIPAddress, 0});

	if (addr.s_addr == INADDR_ANY || addr.s_addr == INADDR_NONE) {
		EXIT();
		return -1;
	}

	inet_ntop(AF_INET, &addr, ipaddr, INET_ADDRSTRLEN);

	fout = fopen(HOSTS_FILE, "w+");
	if (!fout) {
		EXIT();
		return -1;
	}

	fprintf(fout, "127.0.0.1\tlocalhost\n");
	fprintf(fout, "%s\tlogin\n", ipaddr);
	fprintf(fout, "%s\tstart\n", ipaddr);
	fprintf(fout, "%s\tdologin\n", ipaddr);
	fprintf(fout, "%s\tlogout\n", ipaddr);
	fprintf(fout, "%s\tconfig\n", ipaddr);
	fprintf(fout, "%s\tsetup\n", ipaddr);
	fprintf(fout, "%s\texit\n", ipaddr);
	fprintf(fout, "%s\ttime\n", ipaddr);
	fprintf(fout, "%s\tstatus\n", ipaddr);
	fprintf(fout, "%s\tgateway.i-venue.net\n", ipaddr);
	fprintf(fout, "%s\tgateway.tpip.net\n", ipaddr);
	fprintf(fout, "%s\tgateway.global-hotspot.com\n", ipaddr);

	fclose(fout);

	return 0;
}

void lan_ipdown(char *iface)
{
	stop_udhcpc(iface);
	if_ipdown(iface);
}

static int lan_ipup(const char *device, const tr069_selector sel)
{
	int iat = -1;
	struct tr069_instance *ipi;
	struct tr069_instance_node *node;

	stop_udhcpc(device);
	if_ipdown(device);

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface */
	ipi = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							    cwmp__IGD_LANDevice,
							    sel[2],
							    cwmp__IGD_LANDev_i_LANHostConfigManagement,
							    cwmp__IGD_LANDev_i_HostCfgMgt_IPInterface, 0} );
	if (!ipi)
		ereturn("couldn't get LAN config from storage\n");

        for (node = tr069_instance_first(ipi);
             node != NULL;
             node = tr069_instance_next(ipi, node))
	{
		struct tr069_value_table *ipt = DM_TABLE(node->table);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.Enable */
		if (!tr069_get_bool_by_id(ipt, cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_Enable)) {
			EXIT();
			return -1;
		}

		if (iat < 0)
			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceAddressingType */
			iat = tr069_get_enum_by_id(ipt, cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceAddressingType);

		if (iat == cwmp___IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceAddressingType_DHCP) {
			/* DHCP */

			debug(": DHCP client");
			start_udhcpc(device);
			break;
		}
		else if (iat == cwmp___IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceAddressingType_Static) {
                        /* Static */
			struct in_addr ipaddr;
			struct in_addr netmask;

			if (iat != tr069_get_enum_by_id(ipt, cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceAddressingType))
				/* ignore interfaces on anything other than Static */
				continue;

			debug(": Static IP");

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceIPAddress */
			ipaddr = tr069_get_ipv4_by_id(ipt, cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceIPAddress);
			if (ipaddr.s_addr == INADDR_ANY || ipaddr.s_addr == INADDR_NONE)
				ereturn("IPInterfaceIPAddress not set\n");

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceSubnetMask */
			netmask = tr069_get_ipv4_by_id(ipt, cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceSubnetMask);
			if (netmask.s_addr == INADDR_ANY || netmask.s_addr == INADDR_NONE)
				ereturn("IPInterfaceSubnetMask not set\n");

			if_ipup(device, ipaddr, netmask);
		}
		else {
			logx(LOG_ERR, "IPInterfaceAddressingType %d is not supported", iat);
			break;
		}
	}

	if (iat == cwmp___IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceAddressingType_Static)
		if_routes(device, sel);

	start_dhcpd(device, sel);

	EXIT();
	return 0;
}

void devrestart(const tr069_selector s)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const char *dev = NULL;

	debug(": execute for sel: %s", sel2str(b1, s));

	dev = get_if_device(s);
	debug(": got device: %s", dev ? dev : "(NULL)");

	if (dev) {
		if ((s)[1] == cwmp__IGD_LANDevice) {
			debug(": restarting LANDevice %s.", dev);
			lan_ipup(dev, s);
		}
		else if ((s)[1] == cwmp__IGD_WANDevice) {
			debug(": restarting WANDevice %s.", dev);
			wandown();
			wanup();
		}
	}
}

void dm_wan_reconf_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);
	devrestart(sel);
}

void dm_lan_reconf_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);
	devrestart(sel);
}

static int br_ifup(const char *device, const tr069_selector sel)
{
	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return -1;
	}

	/* FIXME: simplistic version */
	if (hs_is_enabled(sel)) {
		vasystem("/usr/sbin/ebtables -A FORWARD -i %s -o %s -j DROP", device, device);
#if defined(WITH_AR7)
		if_marvell();
#endif
	}

	if_linkup(device);
	lan_sched_init(device, sel);
	lan_ipup(device, sel);

	EXIT();
	return 0;
}

static int ofs_ifup(const char *device, const tr069_selector sel)
{
	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return -1;
	}

	if_linkup(device);
	lan_sched_init(device, sel);
	lan_ipup(device, sel);

	EXIT();
	return 0;
}

int wait_for_interface(const char *device, int wait)
{
	int loop, r = 0;

	/* wait wait seconds for our target to become available */
	loop = wait * 20;
	while (loop--) {
		if ((r = if_nametoindex(device)) != 0)
				break;

		debug(": wait for netif '%s' to become available, loop=%i", device, (30 * 20) - loop);
		usleep(1000 * 1000 / 20);
	}
	debug(": got netif '%s' on loop=%i", device, (30 * 20) - loop);

	return r;
}

static int lan_eth_ifup(const char *device, const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct tr069_value_table *ift;
	int r;

	ENTER();
	debug(": device: %s, sel: %s", device, sel2str(b1, sel));

	ift = tr069_get_table_by_selector(sel);
	if (!ift) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANEthernetInterfaceConfig.{i}.Enable */
	if (!tr069_get_bool_by_id(ift, cwmp__IGD_LANDev_i_EthCfg_j_Enable)) {
		EXIT();
		return -1;
	}

	r = wait_for_interface(device, 30);

	if (r != 0) {
		/* the interface is ready to go, add it to it's lan bridge */
		tr069_selector if_sel;

		tr069_selcpy(if_sel, sel);
		if_sel[3] = 0;
		if_add2LANdevice(device, if_sel);
	}

	EXIT();
	return 0;
}

static int _eth_ifup(const char *device, const tr069_selector sel)
{
	/** VAR: InternetGatewayDevice.LANDevice.i.LANEthernetInterfaceConfig */
	if (sel[1] == cwmp__IGD_LANDevice &&
	    sel[3] == cwmp__IGD_LANDev_i_LANEthernetInterfaceConfig) {
		return lan_eth_ifup(device, sel);
	}
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANEthernetInterfaceConfig */
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice */
        else if ((sel[1] == cwmp__IGD_WANDevice &&
		  sel[2] != 0) &&
		 (sel[3] == cwmp__IGD_WANDev_i_WANEthernetInterfaceConfig ||
		  (sel[3] == cwmp__IGD_WANDev_i_WANConnectionDevice &&
		   sel[4] != 0))) {
		return wan_eth_ifup(device, sel);
	}
	/** VAR: InternetGatewayDevice.X_TPOSS_Switch */
        else if (sel[1] == cwmp__IGD_X_TPOSS_Switch) {
		return switch_setup(device, sel);
	}
	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN */
        else if (sel[1] == cwmp__IGD_X_TPOSS_VLAN) {
		return vlan_if_setup(device, sel);
	}
	return 0;
}

static int vlan_ifup(const char *device, const tr069_selector sel)
{
	return _eth_ifup(device, sel);
}

static int eth_ifup(const char *device, const tr069_selector sel)
{
	int r;

	r = _eth_ifup(device, sel);
	if (r == 0)
		vlan_setup(device, sel);
	return r;
}

static int wan_add_cic_conn(const tr069_selector sel, const tr069_selector srv_sel)
{
#if defined(SDEBUG)
	char b1[128], b2[128];
#endif
	struct tr069_instance_node *ccc;
	tr069_id id;

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection */
	tr069_selector cic_sel = { cwmp__InternetGatewayDevice,
				   cwmp__IGD_WANDevice,
				   sel[2],
				   cwmp__IGD_WANDev_i_WANCommonInterfaceConfig,
				   cwmp__IGD_WANDev_i_CommonCfg_Connection, 0};

	ENTER();

	debug(": %s, %s", sel2str(b1, sel), sel2str(b2, srv_sel));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.<DeviceType>.{i} */
	if (srv_sel[0] != cwmp__InternetGatewayDevice ||
	    srv_sel[1] != cwmp__IGD_WANDevice ||
	    srv_sel[2] == 0 ||
	    srv_sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    srv_sel[4] == 0 ||
	    srv_sel[5] == 0 ||
	    srv_sel[6] == 0) {
		EXIT();
		return -1;
	}

	pthread_rwlock_wrlock(&tr069_rwlock);

	id = TR069_ID_AUTO_OBJECT;
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface */
	if ((ccc = tr069_add_instance_by_selector(cic_sel, &id)) == NULL) {
		pthread_rwlock_unlock(&tr069_rwlock);
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection.{i}.ActiveConnectionDeviceContainer */
	tr069_set_selector_by_id(DM_TABLE(ccc->table), cwmp__IGD_WANDev_i_CommonCfg_Con_j_ActiveConnectionDeviceContainer, sel);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection.{i}.ActiveConnectionServiceID */
	tr069_set_selector_by_id(DM_TABLE(ccc->table), cwmp__IGD_WANDev_i_CommonCfg_Con_j_ActiveConnectionServiceID, srv_sel);

	pthread_rwlock_unlock(&tr069_rwlock);

	EXIT();
	return 0;
}

int wan_del_cic_conn(const tr069_selector sel)
{
#if defined (SDEBUG)
	char b1[128];
#endif
	tr069_id id = 0;
        struct tr069_instance *ccc;
        struct tr069_instance_node *node;

	ENTER();

	debug(": %s", sel2str(b1, sel));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice */
	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection */
	ccc = tr069_get_instance_ref_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							   cwmp__IGD_WANDevice,
							   sel[2],
							   cwmp__IGD_WANDev_i_WANCommonInterfaceConfig,
							   cwmp__IGD_WANDev_i_CommonCfg_Connection, 0});
	if (!ccc) {
		EXIT();
		return -1;
	}

        for (node = tr069_instance_first(ccc);
             node != NULL;
             node = tr069_instance_next(ccc, node)) {
		tr069_selector *ccc_sel;

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection.{i}.ActiveConnectionDeviceContainer */
		ccc_sel = tr069_get_selector_by_id(DM_TABLE(node->table),
						   cwmp__IGD_WANDev_i_CommonCfg_Con_j_ActiveConnectionDeviceContainer);
		if (tr069_selcmp(*ccc_sel, sel, TR069_SELECTOR_LEN) == 0) {
			id = node->instance;
			break;
		}
	}

	if (id > 0) {
		debug(": id: %d", id);
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection.{i} */
		tr069_del_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							    cwmp__IGD_WANDevice,
							    sel[2],
							    cwmp__IGD_WANDev_i_WANCommonInterfaceConfig,
							    cwmp__IGD_WANDev_i_CommonCfg_Connection,
							    id, 0 });

	}
	EXIT();
	return 0;
}

static tr069_selector *wan_get_cic_conn(const tr069_selector sel)
{
#if defined (SDEBUG)
	char b1[128];
#endif
        struct tr069_instance *ccc;
        struct tr069_instance_node *node;

	ENTER();

	debug(": %s", sel2str(b1, sel));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice */
	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection */
	ccc = tr069_get_instance_ref_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							   cwmp__IGD_WANDevice,
							   sel[2],
							   cwmp__IGD_WANDev_i_WANCommonInterfaceConfig,
							   cwmp__IGD_WANDev_i_CommonCfg_Connection, 0});
	if (!ccc) {
		EXIT();
		return NULL;
	}

        for (node = tr069_instance_first(ccc);
             node != NULL;
             node = tr069_instance_next(ccc, node)) {
		tr069_selector *ccc_sel;

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection.{i}.ActiveConnectionDeviceContainer */
		ccc_sel = tr069_get_selector_by_id(DM_TABLE(node->table),
						   cwmp__IGD_WANDev_i_CommonCfg_Con_j_ActiveConnectionDeviceContainer);

		if (ccc_sel && tr069_selcmp(*ccc_sel, sel, TR069_SELECTOR_LEN) == 0) {
			EXIT();
			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.Connection.{i}.ActiveConnectionDeviceContainer */
			return tr069_get_selector_by_id(DM_TABLE(node->table),
							cwmp__IGD_WANDev_i_CommonCfg_Con_j_ActiveConnectionServiceID);
		}
	}
	EXIT();
	return NULL;
}

int wan_resolv_conf(char *dns, int override, const char *device)
{
	if (device && *device) {
		char dres[sizeof(RESOLV_CONF) + strlen(device) + 2];

		snprintf(dres, sizeof(RESOLV_CONF) + strlen(device) + 2, "%s-%s", RESOLV_CONF, device);
		debug(": link %s", dres);
		unlink(dres);

		if (!dns || !*dns || override)
			symlink(RESOLV_CONF, dres);
	}

	if (dns) {
		FILE *fout;
		char *s;

		fout = fopen(RESOLV_CONF, "w");
		if (!fout) {
			logx(LOG_ERR, "failed to open %s for writing", RESOLV_CONF);
			return 1;
		}

		while (dns && *dns) {
			s = strchr(dns, ',');
			if (!s)
				fprintf(fout, "nameserver %s\n", dns);
			else {
				fprintf(fout, "nameserver %.*s\n", s - dns, dns);
				s++;
			}
			dns = s;
		}
		fclose(fout);
	}

	return 0;
}

int wan_eth_ifup(const char *device, const tr069_selector sel)
{
#if defined (SDEBUG)
	char b1[128];
#endif
	char buf[20];
	int wan_type;

	tr069_selector srv_sel = { cwmp__InternetGatewayDevice,
				   cwmp__IGD_WANDevice,
				   sel[2],
				   cwmp__IGD_WANDev_i_WANConnectionDevice,
				   sel[4], 0, 0, 0, 0, 0 };

	struct tr069_instance *tab;
	struct tr069_instance_node *ift_node;
	struct tr069_value_table *ift;
	struct tr069_value_table *if_ipc = NULL;
	struct tr069_instance_node *if_ipc_node;
	struct tr069_value_table *if_pppc = NULL;
	struct tr069_instance_node *if_pppc_node;

	ENTER();

	debug(": sel: %s", sel2str(b1, sel));
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice */
	if (sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0 ||
	    sel[5] != 0) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANCommonInterfaceConfig.EnabledForInternet */
	if (!tr069_get_bool_by_selector((tr069_selector) { cwmp__InternetGatewayDevice,
							   cwmp__IGD_WANDevice,
							   sel[2],
							   cwmp__IGD_WANDev_i_WANCommonInterfaceConfig,
							   cwmp__IGD_WANDev_i_CommonCfg_EnabledForInternet, 0 })) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	ift_node = tr069_get_instance_node_by_selector(sel);
	if (!ift_node) {
		EXIT();
		return -1;
	}
	ift = DM_TABLE(ift_node->table);

	debug(": ift: %p", ift);

	if_ipc = NULL;
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection */
	if ((tab = tr069_get_instance_ref_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection)) != NULL)
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.1 */
		if_ipc_node = tr069_get_instance_node_by_id(tab, 1);
	if (if_ipc_node)
		if_ipc = DM_TABLE(if_ipc_node->table);

	debug(": if_ipc: %p", if_ipc);

	if_pppc = NULL;
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection */
	if ((tab = tr069_get_instance_ref_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection)) != NULL)
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.1 */
		if_pppc_node = tr069_get_instance_node_by_id(tab, 1);
	if (if_pppc_node)
		if_pppc = DM_TABLE(if_pppc_node->table);

	debug(": if_pppc: %p", if_pppc);

	/* FIXME: multiple aliases ??? */
	wan_type = 0;
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.Enable */
	if (if_ipc &&
	    tr069_get_bool_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_Enable)) {
		/* Static / DHCP WAN connection */
		wan_type = 1;
	}
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Enable */
	else if (if_pppc &&
		 tr069_get_bool_by_id(if_pppc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Enable)) {
		wan_type = 2;
	}
	debug(": wan_type: %d", wan_type);

	if (!wan_type) {
		EXIT();
		return -1;
	}

	wait_for_interface(device, 30);
	char *mac = getifmac(device, buf);

	switch (wan_type) {
		case 1: {
			int iat;

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.DNSEnabled */
			if (tr069_get_bool_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_DNSEnabled))
				/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.DNSServers */
				/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.DNSOverrideAllowed */
				wan_resolv_conf(tr069_get_string_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_DNSServers),
						tr069_get_bool_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_DNSOverrideAllowed),
						device);

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.AddressingType */
			iat = tr069_get_enum_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_AddressingType);
			switch (iat) {
				/* DHCP */
				case 0:
					if (mac)
						tr069_set_string_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_MACAddress, mac);

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.1 */
					srv_sel[5] = cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection;
					srv_sel[6] = 1;

					if_linkup(device);
					start_udhcpc(device);
					break;

				/* Static */
				case 1: {
					struct in_addr ipaddr;
					struct in_addr netmask;
					struct in_addr bcast;
					struct in_addr gw;

					char ipaddr_buf[INET_ADDRSTRLEN];
					char bcast_buf[INET_ADDRSTRLEN];

					int plen;

					if (mac)
						tr069_set_string_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_MACAddress, mac);

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i} */
					srv_sel[5] = cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection;
					srv_sel[6] = 1;

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.ExternalIPAddress */
					ipaddr = tr069_get_ipv4_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_ExternalIPAddress);
					if (ipaddr.s_addr == INADDR_ANY || ipaddr.s_addr == INADDR_NONE)
						ereturn("ExternalIPAddress not set\n");

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.SubnetMask */
					netmask = tr069_get_ipv4_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_SubnetMask);
					if (netmask.s_addr == INADDR_ANY || netmask.s_addr == INADDR_NONE)
						ereturn("SubnetMask not set\n");

					if_linkup(device);
					if_ipup(device, ipaddr, netmask);

					/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.DefaultGateway */
					gw = tr069_get_ipv4_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_DefaultGateway);
					if (gw.s_addr != INADDR_ANY && gw.s_addr != INADDR_NONE)
						vasystem("ip route add default via %s dev %s",
							 inet_ntop(AF_INET, &gw, ipaddr_buf, INET_ADDRSTRLEN), device);

					wan_ipup(device, sel);
					break;
				}
				default:
					//fprintf(stderr, "WANIPConnection.%d.AddressingType %s is not supported\n", ip_ifc, iat);
					EXIT();
					return -1;
			}
			wan_sched_init(device, sel);

			break;
		}
		case 2:
			if (tr069_get_bool_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_DNSEnabled))
				/* FIXME: this works only if the WAN PPP interface is ppp0, see also ppp package /etc/ppp/resolv.conf symlink
				 */

				/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.DNSServers */
				/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.DNSOverrideAllowed */
				wan_resolv_conf(tr069_get_string_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_DNSServers),
						tr069_get_bool_by_id(if_ipc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_DNSOverrideAllowed),
						device);

			if (mac)
				tr069_set_string_by_id(if_pppc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_MACAddress, mac);

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.1 */
			srv_sel[5] = cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection;
			srv_sel[6] = 1;

			if_linkup(device);
			pppoe_ifup(device, sel[2], ift_node, if_pppc_node);
			break;
	}

	wan_add_cic_conn(sel, srv_sel);
	EXIT();
	return 0;
}

int wan_ifdown(const char *device, const tr069_selector sel)
{
	struct tr069_value_table *ift;

	ENTER();

	debug(": sel: %p", sel);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice */
	if (sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	ift = tr069_get_table_by_selector(sel);
	if (!ift) {
		EXIT();
		return -1;
	}

	/* shutdown wan interface */
	ppp_stop_condev(device, sel);
	stop_udhcpc(device);
	stop_dhcpd(device);
	if_ipdown(device);
	if_linkdown(device);

	wan_del_cic_conn(sel);

	EXIT();
	return 0;
}

int test_system_up(void)
{
	int r;

	pthread_mutex_lock(&system_up_mutex);
	r = is_system_up;
	pthread_mutex_unlock(&system_up_mutex);

	return r;
}

void system_up(void)
{
	pthread_mutex_lock(&system_up_mutex);
	is_system_up = 1;
	pthread_mutex_unlock(&system_up_mutex);

	start_flsc();

	syslog_config();
	hosts_file();
	dnsmasq_config();
	start_dnsmasq();

#ifdef WITH_SCG_FW
	init_scg_zones_radius();
#endif

	init_l2tpd();
	reconf_l2tpd();

	luci_config();
	httpd_reload();

#if 0 /* proxyd currently unusable */
	start_proxy();
#endif
	start_snmpd();
	scg_acl_init();
	ipt_init();

//	start_ppp_server();

	if (!ntpd_running)
		start_wan_ntpd();

	tr069_startup();
}

void update_LANdeviceMAC(const char *device, const tr069_selector sel)
{
	struct tr069_instance_node *node;
	char buf[20];

	ENTER();

	debug(": mac: %s", device ? device : "(NULL)");

	char *mac = getifmac(device, buf);
	if (mac) {
		tr069_selector cfg;

		debug(": mac: %s", mac);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANEthernetInterfaceConfig.{i}.MACAddress */
		tr069_selcpy(cfg, sel);
		cfg[3] = cwmp__IGD_LANDev_i_LANEthernetInterfaceConfig;
		cfg[4] = 1;
		cfg[5] = cwmp__IGD_LANDev_i_EthCfg_j_MACAddress;
		cfg[6] = 0;

		tr069_set_string_by_selector(cfg, mac, DV_UPDATED);
	}

	EXIT();
}

int if_add2LANdevice(const char *device, const tr069_selector sel)
{
	const char *br;
	const char *ofs;

	br = get_br_device(sel);
	if (!br) {
		ofs = get_ofs_device(sel);
		if (!ofs) {
			/* this a non-bridge local interface */
			if_linkup(device);
			lan_sched_init(device, sel);
			lan_ipup(device, sel);
			update_LANdeviceMAC(device, sel);
		} else {
			ofs_addif(ofs, device);
			if_linkup(device);
			update_LANdeviceMAC(ofs, sel);
		}
	} else {
		br_addif(br, device);
		if_linkup(device);
		update_LANdeviceMAC(br, sel);
	}

	return 0;
}

static void dump_if(void)
{
        struct tr069_instance_node *node;

	ENTER();
	if (!if_map) {
		EXIT();
		return;
	}
	if (!if_instances) {
		EXIT();
		return;
	}

	pthread_rwlock_rdlock(&tr069_rwlock);
	debug(": if_map");
        for (node = tr069_instance_first(if_map);
             node != NULL;
             node = tr069_instance_next(if_map, node)) {
		struct tr069_value_table *ifm = DM_TABLE(node->table);
		debug(": %s => %d",
		      tr069_get_string_by_id(ifm, cwmp__IGD_IfMap_IfType_i_Name),
		      tr069_get_enum_by_id(ifm, cwmp__IGD_IfMap_IfType_i_Type));
	}

	debug(": if_instances");
        for (node = tr069_instance_first(if_instances);
             node != NULL;
             node = tr069_instance_next(if_instances, node)) {
		struct tr069_value_table *ift = DM_TABLE(node->table);
		debug(": %s => %p",
		      tr069_get_string_by_id(ift, cwmp__IGD_IfMap_If_i_Name),
		      tr069_get_table_by_id(ift, cwmp__IGD_IfMap_If_i_Device));
	}
	pthread_rwlock_unlock(&tr069_rwlock);
}

void if_startup()
{
	struct tr069_value_table *ift;

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap */
	ift = tr069_get_table_by_selector((tr069_selector) { cwmp__InternetGatewayDevice,
							     cwmp__IGD_X_TPOSS_InterfaceMap, 0 });
	if (!ift) {
		logx(LOG_ERR, "%s", "couldn't get InterfaceType from storage");
		return;
	}
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType */
	if_map = tr069_get_instance_ref_by_id(ift, cwmp__IGD_IfMap_InterfaceType);
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface */
	if_instances = tr069_get_instance_ref_by_id(ift, cwmp__IGD_IfMap_Interface);

	br_init(ift);
	ofs_init(ift);

	//	dump_if();
}

int _if_add2ifmap(const char *iface, const tr069_selector ifref)
{
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device */
	tr069_selector nif = { cwmp__InternetGatewayDevice,
			       cwmp__IGD_X_TPOSS_InterfaceMap,
			       cwmp__IGD_IfMap_Interface,
			       0,
			       cwmp__IGD_IfMap_If_i_Device,
			       0, 0 };
	tr069_selector shrtref;
	struct tr069_instance_node *vif;
	tr069_id id;

	ENTER();

	id = TR069_ID_AUTO_OBJECT;
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */
	if ((vif = tr069_add_instance_by_selector(nif, &id)) == NULL) {
		EXIT();
		return -1;
	}

	nif[3] = id;

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
	tr069_set_string_by_id(DM_TABLE(vif->table), cwmp__IGD_IfMap_If_i_Name, iface);

	if(strncmp(iface, "ppp", 3)) {

		tr069_selcpy(shrtref, ifref);
		shrtref[3] = 0;

		id = TR069_ID_AUTO_OBJECT;
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */
		if ((vif = tr069_add_instance_by_selector(nif, &id)) == NULL) {
			EXIT();
			return -1;
		}

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
		tr069_set_selector_by_id(DM_TABLE(vif->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference, shrtref);

	}

	id = TR069_ID_AUTO_OBJECT;
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */
	if ((vif = tr069_add_instance_by_selector(nif, &id)) == NULL) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
	tr069_set_selector_by_id(DM_TABLE(vif->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference, ifref);

	EXIT();
	return 0;
}

int if_add2ifmap(const char *iface, const tr069_selector ifref)
{
	int ret;

	pthread_rwlock_wrlock(&tr069_rwlock);
	ret = _if_add2ifmap(iface, ifref);
	pthread_rwlock_unlock(&tr069_rwlock);

	return ret;
}

int ifmap_remove_if(const char *device)
{
	const struct tr069_instance_node *dnode;

	ENTER();

	if (!(dnode = get_interface_node_by_name(device))) {
		EXIT();
		return -1;
	}

	ifmap_remove_if_by_ref(dnode);

	EXIT();
	return 0;
}

int ifmap_remove_if_by_ref(const struct tr069_instance_node *node)
{
	tr069_id id = 0;

	ENTER();

	if (!node) {
		EXIT();
		return -1;
	}

	id = node->instance;

	if (id > 0) {
		debug("(): id: %d", id);
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */
		tr069_del_table_by_selector((tr069_selector) { cwmp__InternetGatewayDevice,
							       cwmp__IGD_X_TPOSS_InterfaceMap,
							       cwmp__IGD_IfMap_Interface,
							       id, 0 });
	}

	EXIT();
	return 0;
}

int call_if_func(const char *device, struct tr069_instance *base, int direction,
			int (*func)(const char *device, const tr069_selector sel))
{
	char buf[128];
	struct tr069_instance_node *node;

	ENTER();

	if (!base) {
		EXIT();
		return -1;
	}

        for (node = tr069_instance_first(base);
             node != NULL;
             node = tr069_instance_next(base, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */

		struct tr069_value_table *d = DM_TABLE(node->table);
		tr069_selector           *sel;

		debug(": device: %d, %p", node->instance, d);

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
		sel = tr069_get_selector_by_id(d, cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
		if (!sel)
			continue;

		debug(": selector: %s", sel2str(buf, *sel));

		func(device, *sel);
	}

	EXIT();
	return 0;
}

static int ifup(const char *device, struct tr069_instance *base)
{
	int r = 0;

	switch (get_if_type(device)) {
		/* LAN stuff */
#if defined(HAVE_TIAP)
		case ifc_TIAP:
			r = call_if_func(device, base, IF_UP, tiap_ifup);
			break;
#endif
		case ifc_Atheros:
			r = call_if_func(device, base, IF_UP, madwifi_create_if);
			break;
		case ifc_AtherosVAP:
			r = call_if_func(device, base, IF_UP, madwifi_ifup);
			break;
		case ifc_BRCM43xxWL:
			r = brcm43xxwl_ifup(device, base); /* FIXME FIXME FIXME */
			break;
		case ifc_BroadcomWDS:
			r = brcm43xxwl_wdsup(device);
			break;
		case ifc_VLAN:
			r = call_if_func(device, base, IF_UP, vlan_ifup);
			break;
		case ifc_Ethernet:
			r = call_if_func(device, base, IF_UP, eth_ifup);
			break;
		case ifc_Layer2Bridge:
			r = call_if_func(device, base, IF_UP, br_ifup);
			break;
		case ifc_OFSwitch:
			r = call_if_func(device, base, IF_UP, ofs_ifup);
			break;

			/* WAN stuff */
#if defined(WITH_ATM)
		case ifc_ADSL:
			r = call_if_func(device, base, IF_UP, adsl_ifup);
			break;
		case ifc_ATM:
			r = call_if_func(device, base, IF_UP, atm_ifup);
			break;
		case ifc_ATMBridge:
			r = call_if_func(device, base, IF_UP, br2684_ifup);
			break;
		case ifc_IPoA:
			r = call_if_func(device, base, IF_UP, atm_ipoa_ifup);
			break;
#endif
		case ifc_PPP:
			// r = call_if_func(device, base, IF_UP, ppp_ifup);
			break;
	}

	return r;
}

static int wan_ipup(const char *device, const char *link)
{
	int r, ift;
	tr069_selector *sel = NULL;

	ENTER();

	ift = get_if_type(device);

	switch (ift) {
	case ifc_PPP: {
		char *s;
		int dev, conn, instance;

		if (strcmp(link, "lng") == 0) {
			r = lng_ipup(device, (tr069_selector){cwmp__InternetGatewayDevice,
						cwmp__IGD_X_TPLINO_NET_NetworkGateway, 0 });

			EXIT();
			return r;
		}

		s = strchr(link, '.');
		if (!s) {
			EXIT();
			return 0;
		}
		*s++ = '\0';
		r = sscanf(s, "%d.%d.%d", &dev, &conn, &instance);
		debug(": %d, %p, %d, %d, %d", r, link, dev, conn, instance);
		if (r != 3 || strcmp(link, "wan") != 0) {
			EXIT();
			return 0;
		}

		sel = &(tr069_selector){cwmp__InternetGatewayDevice,
				        cwmp__IGD_WANDevice,
				        dev,
				        cwmp__IGD_WANDev_i_WANConnectionDevice,
				        conn, 0};

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i} */
		r = ppp_ipup(device, (tr069_selector){cwmp__InternetGatewayDevice,
						      cwmp__IGD_WANDevice,
						      dev,
						      cwmp__IGD_WANDev_i_WANConnectionDevice,
						      conn,
						      cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
						      instance, 0});
		break;
	}

	case ifc_Ethernet: {
		struct tr069_instance *base;
		struct tr069_instance_node *d;

		base = get_if_layout(device);
		if (!base) {
			EXIT();
			return 0;
		}

		d = tr069_instance_first(base);
		if (!d) {
			EXIT();
			return 0;
		}

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
		sel = tr069_get_selector_by_id(DM_TABLE(d->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
		if (!sel) {
			EXIT();
			return 0;
		}

		httpd_reload();

		r = 1;
		break;
	}

	default:
		r = 1;
		break;
	}


	if (sel)
		if_routes(device, *sel);

	set_fw_wan_nat(1);
	stop_wan_ntpd();
	start_wan_ntpd();

	EXIT();
	return r;
}

static int ppp_ipdown_helper(const char *device, const tr069_selector sel)
{
	if (sel[1] == cwmp__IGD_WANDevice)
		return ppp_ipdown(device, sel);
	else if (sel[1] == cwmp__IGD_X_TPLINO_NET_NetworkGateway)
		return lng_ipdown(device, sel);
	return 0;
}

void do_uevent(const char *class, const char *action, const char *device, const char *info)
{
	ENTER();
	debug(": class: %s, action: %s, device: %s, info: %s", class, action, device, info ? info : "NULL");

	if (strncasecmp(class, "net", 3) == 0) {
		struct tr069_instance *base;

		base = get_if_layout(device);

		debug(": if_type(%s): %d (%p)", device, get_if_type(device), base);

		if (strncasecmp(action, "register", 8) == 0 ||
		    strncasecmp(action, "add", 3) == 0) {

#ifdef WITH_BULLET
			if (get_if_type(device) == ifc_Ethernet)
				sleep(1);
#endif
			ifup(device, base);

		} else if (strncasecmp(action, "unregister", 10) == 0 ||
			   strncasecmp(action, "remove", 6) == 0) {
			int r = 0;
			int type;

			type = get_if_type(device);
			switch (type) {
#if defined(WITH_ATM)
				case ifc_ATMBridge:
					r = call_if_func(device, base, IF_DOWN, br2684_ifdown);
					break;
#endif
				case ifc_PPP:
					r = call_if_func(device, base, IF_DOWN, ppp_ipdown_helper);
					break;
			}
			ifmap_remove_if(device);
		} else if (strncasecmp(action, "ipup", 4) == 0) {
			wan_ipup(device, info);

		} else if (strncasecmp(action, "ipdown", 6) == 0) {
			int type;

			type = get_if_type(device);
			switch (type) {
			case ifc_Ethernet:
				httpd_reload();
			}
		}
	} else if (strncasecmp(class, "USB", 3) == 0) {
		logx(LOG_ERR, "%s", "unsupported hotplug class");
	} else
		logx(LOG_ERR, "%s", "unsupported hotplug class");

	EXIT();
}

static void *hotplug_thread(void *arg)
{
	const char *argv[10];
	int argc = 0;
	char *cmd = (char *)arg;

	chomp(cmd);
	debug(": %s", cmd);

	memset(argv, 0, sizeof(argv));
	while(argc < 10 && cmd && *cmd) {
		argv[argc++] = cmd;

		if ((cmd = strchr(cmd, ' ')) != NULL)
			*cmd++ = '\0';
	}

	for (int i = 0; i < argc; i++)
		debug(": argv[%d]: %s", i, argv[i]);

	if (argc >= 3)
		do_uevent(argv[0], argv[1], argv[2], argv[3]);

	free(cmd);
	return NULL;
}

void hotplug(const char *cmd)
{
	pthread_t tid;
	char *s;

	s = strdup(cmd);
	pthread_create(&tid, NULL, hotplug_thread, (void *)s);
	pthread_detach(tid);
}

int ifdown(const char *device, struct tr069_instance *base)
{
	/* take an interface down */

	int r = 0;

	ENTER();

	debug(": device: %s, type: %d", device, get_if_type(device));
	switch (get_if_type(device)) {
		/* LAN stuff */
#if defined(HAVE_TIAP)
		case ifc_TIAP:
			break;
#endif
		case ifc_Atheros:
			break;
		case ifc_AtherosVAP:
			break;
		case ifc_BRCM43xxWL:
			break;
		case ifc_VLAN:
		case ifc_Ethernet:
			r = call_if_func(device, base, IF_DOWN, wan_ifdown);
			break;
		case ifc_Layer2Bridge:
			break;
		case ifc_OFSwitch:
			break;

			/* WAN stuff */
#if defined(WITH_ATM)
		case ifc_ADSL:
			break;
		case ifc_ATM:
			atm_linkdown_all();
			break;
		case ifc_ATMBridge:
			r = call_if_func(device, base, IF_DOWN, br2684_ifdown);
			break;
#endif
		case ifc_PPP:
			r = call_if_func(device, base, IF_DOWN, ppp_stop_condev);
			break;
	}

	EXIT();
	return r;

}

struct ifup_devs {
	tr069_selector sel;
	char device[IF_NAMESIZE];
};

void wanup(void)
{
	int wdev_cnt = 0;
	struct ifup_devs *wdevs = NULL;
	struct tr069_instance_node *node;

	ENTER();

	if (!if_instances) {
		EXIT();
		return;
	}

        for (node = tr069_instance_first(if_instances);
             node != NULL;
             node = tr069_instance_next(if_instances, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */

		struct tr069_value_table *ifi = DM_TABLE(node->table);
		struct tr069_instance *ifd;
		struct tr069_instance_node *ifd_node;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device */
		ifd = tr069_get_instance_ref_by_id(ifi, cwmp__IGD_IfMap_If_i_Device);
		debug(": ifd: %p, (%s)", ifd,
		      tr069_get_string_by_id(ifi, cwmp__IGD_IfMap_If_i_Name));
		if (!ifd)
			continue;

		for (ifd_node = tr069_instance_first(ifd);
		     ifd_node != NULL;
		     ifd_node = tr069_instance_next(ifd, ifd_node)) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */
			struct tr069_value_table *ifdi = DM_TABLE(ifd_node->table);
			tr069_selector           *sel;

			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
			sel = tr069_get_selector_by_id(ifdi, cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
			debug(": sel: %p", sel);
			if (!sel)
				continue;

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
			if ((*sel)[1] != cwmp__IGD_WANDevice ||
			    (*sel)[2] == 0 ||
			    (*sel)[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
			    (*sel)[4] == 0)
				continue;

			debug(": do ifup later: %s", tr069_get_string_by_id(ifi, cwmp__IGD_IfMap_If_i_Name));

			if ((wdev_cnt % 16) == 0)
				wdevs = realloc(wdevs, sizeof(struct ifup_devs) * (wdev_cnt + 16));

			tr069_selcpy(wdevs[wdev_cnt].sel, *sel);
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
			strncpy(wdevs[wdev_cnt].device, tr069_get_string_by_id(ifi, cwmp__IGD_IfMap_If_i_Name), IF_NAMESIZE);
			wdevs[wdev_cnt].device[IF_NAMESIZE - 1] = '\0';
			wdev_cnt++;
		}
	}

	debug(": wdev: %d", wdev_cnt);
	for (int i = 0; i < wdev_cnt; i++) {
		debug(": do ifup: %s", wdevs[i].device);
		ifup(wdevs[i].device, get_if_layout(wdevs[i].device));
	}
	free(wdevs);

	EXIT();
}

void wandown(void)
{
	int wdev_cnt = 0;
	struct ifup_devs *wdevs = NULL;
	struct tr069_instance_node *node;

	ENTER();

	if (!if_instances) {
		EXIT();
		return;
	}

        for (node = tr069_instance_first(if_instances);
             node != NULL;
             node = tr069_instance_next(if_instances, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */

                struct tr069_value_table *ifi = DM_TABLE(node->table);
                struct tr069_instance *ifd;
                struct tr069_instance_node *ifd_node;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device */
		ifd = tr069_get_instance_ref_by_id(ifi, cwmp__IGD_IfMap_If_i_Device);
		debug(": ifd: %p, (%s)", ifd,
		      tr069_get_string_by_id(ifi, cwmp__IGD_IfMap_If_i_Name));
		if (!ifd)
			continue;

               for (ifd_node = tr069_instance_last(ifd);
                     ifd_node != NULL;
                     ifd_node = tr069_instance_prev(ifd, ifd_node)) {
		       /** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */

                        struct tr069_value_table *ifdi = DM_TABLE(ifd_node->table);
			const char *ifn;
			tr069_selector           *sel;

			debug(": ifdi: %p", ifdi);

			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
			sel = tr069_get_selector_by_id(ifdi, cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
			debug(": sel: %p", sel);
			if (!sel)
				continue;

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
			if ((*sel)[1] != cwmp__IGD_WANDevice ||
			    (*sel)[2] == 0 ||
			    (*sel)[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
			    (*sel)[4] == 0)
				continue;

			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
			ifn = tr069_get_string_by_id(ifi, cwmp__IGD_IfMap_If_i_Name);
			if (!ifn || !*ifn)
				continue;

			if ((wdev_cnt % 16) == 0)
				wdevs = realloc(wdevs, sizeof(struct ifup_devs) * (wdev_cnt + 16));

			tr069_selcpy(wdevs[wdev_cnt].sel, *sel);
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
			strncpy(wdevs[wdev_cnt].device, tr069_get_string_by_id(ifi, cwmp__IGD_IfMap_If_i_Name), IF_NAMESIZE);
			wdevs[wdev_cnt].device[IF_NAMESIZE - 1] = '\0';
			wdev_cnt++;
		}
	}

	debug(": wdev: %d", wdev_cnt);
	for (int i = 0; i < wdev_cnt; i++) {
		struct tr069_instance *base;

		base = get_if_layout(wdevs[i].device);
		debug(": do ifdown: %s, %p", wdevs[i].device, base);

		if (base)
			ifdown(wdevs[i].device, base);
	}
	free(wdevs);

	EXIT();
}

void dm_change_hname_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const char *hostname,*dot;

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	hostname = tr069_get_string_by_selector(sel);
	if (hostname){
		dot = strchrnul(hostname, (int)'.');
		sys_echo("/proc/sys/kernel/hostname", "%.*s\n", dot-hostname, hostname);
	}
}

void dm_dev_rev_chng_action(const tr069_selector sel,
			    enum dm_action_type type __attribute__((unused)))
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const char *dev;
	tr069_selector tsel, *vref;

	ENTER(": Device reference changed: %s", tr069_sel2name(sel, b1, sizeof(b1)));

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
	tr069_selcpy(tsel, sel);

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
	tsel[4] = cwmp__IGD_IfMap_If_i_Name;
	tsel[5] = 0;

	if (!(dev = tr069_get_string_by_selector(tsel))) {
		EXIT();
		return;
	}
	debug("(): Master Device is: %s", dev);

	if (!(vref = tr069_get_selector_by_selector(sel))) {
		EXIT();
		return;
	}
	debug("(): Reference changed to: %s", tr069_sel2name(*vref, b1, sizeof(b1)));

	/* If the reference pointed to a VLAN this will bring it up. */
	vlan_if_setup(dev, *vref);

	EXIT();
}

