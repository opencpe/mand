#ifndef __IFUP_H
#define __IFUP_H

#include <stdarg.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_action.h"

#include "process.h"

#define ETH_DEVICE "eth%d"
#define ATM_DEVICE "atm%d"
#define ATM_BR_DEVICE "nas%d"
#define WAN_DEVICE "eth%d"
#define WIFI_DEVICE "wifi%d"
#define UDHCPC "/sbin/udhcpc"
#define PID_DIR "/var/run"
#define RESOLV_CONF "/var/etc/resolv.conf"
#define DNSMASQ "/usr/sbin/dnsmasq"
#define DNSMASQ_CONF "/var/etc/dnsmasq.conf"
#define HOSTS_FILE "/var/etc/hosts"
#define PPP_DEVICE "ppp0"
#define HOTSPOTD "/usr/bin/gateway"
#define HOTSPOT_IPFILTER "/jffs/etc/gateway_ipfilter.conf"
#define HOTSPOT_CONF "/jffs/etc/gateway.conf"
#define NTPD "/usr/sbin/ntpd"
#define NTPD_USER "ntp"
#define NTPD_CFG "/tmp/etc/ntpd.conf"

#define LUCI_CFG "/tmp/etc/luci"
#define LUCITTPD "/usr/bin/lucittpd"
#define LUCITTPD_CFG "/tmp/etc/lucittpd"
#define LUCITTPD_SSL_KEY "/jffs/etc/ssl/gateway.key"
#define LUCITTPD_SSL_CRT "/jffs/etc/ssl/gateway.crt"
#define LUCITTPD_SSL_CA "/jffs/etc/ssl/gateway.ca"

struct device_info_t {
	struct device_info_t *next;
	int                  type;
	int                  driver;
	int                  id;
	int                  ifname;
};

/*
struct device_driver {
	int type;
	int *init(int card, int ifc);
	int *deinit(int card, int ifc);
};
*/

struct httpd_info_t {
	struct httpd_info_t	*next;

	enum {
		HTTPD_STATE_START,
		HTTPD_STATE_STARTED,
		HTTPD_STATE_INFORM
	} state;
	tr069_id		inst;
	const char		*server_id;

	int			id;
};

extern pthread_rwlock_t tr069_rwlock;

void get_lan_iface(int card, int ifc, char *iface, int size);
void get_atm_iface(int card, int ifc, char *iface, int size);
void lan_ipdown(char *iface);
const struct tr069_instance_node *get_interface_node_by_name(const char *);
const struct tr069_instance_node *get_interface_node_by_selector(const tr069_selector sel) __attribute__((nonnull (1)));
const char *get_if_device(const tr069_selector sel) __attribute__((nonnull (1)));
const char *get_wan_device(int id);
const tr069_selector *get_wan_device_sel(int id);
struct in_addr get_wan_ip(int id);
int get_wan_nat(int id);
struct tr069_instance *get_if_layout(const char *if_name);

void dm_restart_syslog_action(const tr069_selector sel, enum dm_action_type type);
void dm_wan_reconf_action(const tr069_selector, enum dm_action_type);
void dm_lan_reconf_action(const tr069_selector, enum dm_action_type);
void dm_vlan_reconf_action(const tr069_selector, enum dm_action_type);
void dm_dev_rev_chng_action(const tr069_selector, enum dm_action_type);
void dm_check_ntpd_action(const tr069_selector sel, enum dm_action_type type);
void dm_change_hname_action(const tr069_selector sel, enum dm_action_type type);
void dm_httpd_restart_action(const tr069_selector sel, enum dm_action_type type);
void dm_httpd_reload_action(const tr069_selector sel, enum dm_action_type type);

int wait_for_interface(const char *device, int wait);

void if_startup(void);
int switch_setup(const char *device, const tr069_selector) __attribute__((nonnull (2)));
int vlan_up(const char *device, int tag, const tr069_selector sel) __attribute__((nonnull (3)));
void vlan_setup(const char *device, const tr069_selector sel) __attribute__((nonnull (2)));
int vlan_if_setup(const char *device, const tr069_selector sel) __attribute__((nonnull (2)));

#ifdef WITH_BRCM43XX
int brcm43xxwl_ifup(const char *device, struct tr069_instance *base);
int brcm43xxwl_wdsup(const char *device);
#else
static inline int brcm43xxwl_ifup(const char *device __attribute__ ((unused)), struct tr069_value_table *st __attribute__ ((unused))) { return -1; };
static inline int brcm43xxwl_wdsup(const char *device __attribute__ ((unused))) { return -1; };
#endif

#if defined(WITH_BCM63XX)
int bcm63xx_atm_drvstatus(void);
#endif

int _if_add2ifmap(const char *iface, const tr069_selector ifref) __attribute__((nonnull (2)));
int if_add2LANdevice(const char *, const tr069_selector) __attribute__((nonnull (2)));
int if_add2ifmap(const char *, const tr069_selector) __attribute__((nonnull (2)));
int ifmap_remove_if_by_ref(const struct tr069_instance_node *);

int wan_eth_ifup(const char *device, const tr069_selector) __attribute__((nonnull (2)));

int adsl_ifup(const char *device, const tr069_selector) __attribute__((nonnull (2)));
int atm_start(const char *device, const tr069_selector) __attribute__((nonnull (2)));
int atm_ifup(const char *device, const tr069_selector) __attribute__((nonnull (2)));
int atm_ipoa_ifup(const char *device, const tr069_selector) __attribute__((nonnull (2)));

int atm_linkdown_all(void);
int br2684_ifup(const char *device, const tr069_selector) __attribute__((nonnull (2)));
int br2684_ifdown(const char *device, const tr069_selector) __attribute__((nonnull (2)));

int ppp_startif(const char *device, const char *conff, const tr069_selector) __attribute__((nonnull (3)));
int ppp_stopif(const char *device, const tr069_selector) __attribute__((nonnull (2)));
int ppp_stop_condev(const char *device, const tr069_selector sel) __attribute__((nonnull (2)));
void ppp_stop_all(void);
void ppp_defaults(FILE *fout, struct tr069_value_table *ift);

int ppp_ipup(const char *device, const tr069_selector sel) __attribute__((nonnull (2)));
int ppp_ipdown(const char *device, const tr069_selector sel) __attribute__((nonnull (2)));

int pppoe_ifup(const char *, tr069_id, struct tr069_instance_node *, struct tr069_instance_node *);

void if_linkup(const char *iface);
void if_linkdown(const char *iface);

int wan_ifdown(const char *device, const tr069_selector) __attribute__((nonnull (2)));

void devrestart(const tr069_selector);

/* udhcpc */
void start_udhcpc(const char *iface);
int stop_udhcpc(const char *iface);
int signal_udhcpc(const char *iface, int signal);

/* bridge */
const char *get_br_device(const tr069_selector sel) __attribute__((nonnull (1)));
int br_addif(const char *br, const char *device);
int find_port4mac(const char *brname, u_int8_t mac_addr[6]);
void br_init(struct tr069_value_table *ift);

/* OFSwitch */
const char *get_ofs_device(const tr069_selector sel) __attribute__((nonnull (1)));
int ofs_addif(const char *br, const char *device);
void ofs_init(struct tr069_value_table *ift);
void start_flsc(void);

/* net_sched */
void wan_sched_init(const char *iface, const tr069_selector ifref) __attribute__((nonnull (2)));
void lan_sched_init(const char *iface, const tr069_selector ifref) __attribute__((nonnull (2)));
void net_sched_init(void);

void wanup(void);
void wandown(void);
int test_system_up(void);
void system_up(void);
void hotplug(const char *cmd);
void do_uevent(const char *class, const char *action, const char *device, const char *info);

/* helper */
enum {
	IF_NONE,
	IF_UP,
	IF_DOWN,
};


int call_if_func(const char *device, struct tr069_instance *base, int direction,
		 int (*func)(const char *device, const tr069_selector sel));

char *getifmac(const char *dev, char *buf);
void update_LANdeviceMAC(const char *device, const tr069_selector sel);

#endif
