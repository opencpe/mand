#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_notify.h"
#include "tr069_action.h"

//#define FILEOUT
#define SDEBUG
#include "debug.h"

#include "ifup.h"
#include "firewall.h"
#include "connmark.h"
#include "proxy.h"

#define GW_HTTP_PORT      3128
#define GW_HTTPS_PORT      443

static int fw_running = 0;

/* map enum to name */
static const char *proto_names[] = { "tcp", "udp" };

enum ipt_type {
	RAW,
	MANGLE,
	NAT,
	FILTER,
	IPT_TYPE_MAX
};

struct ipt_entry {
	char *name;
	unsigned int flag;
};

#define IF_NOT_FLAG(x, flag)			\
	if ((x & flag) != flag)

#define IF_FLAG(x, flag, name)				\
	if ((x & flag) != flag) {			\
		debug("(): flag %s not set", name);	\
	} else

#define FLAG_DONE           (1 << 31)

#define TARGET_ACCEPT       (1 <<  0)
#define TARGET_DROP         (1 <<  1)
#define TARGET_REJECT       (1 <<  2)
#define TARGET_NOTRACK      (1 <<  3)
#define TARGET_TCPMSS       (1 <<  4)
#define TARGET_LOG          (1 <<  5)
#define TARGET_REDIRECT     (1 <<  6)
#define TARGET_MASQUERADE   (1 <<  7)
#define TARGET_MARK         (1 <<  8)
#define TARGET_DNAT         (1 <<  9)
#define TARGET_SNAT         (1 << 10)
#define TARGET_CLASSIFY     (1 << 11)
#define TARGET_SET          (1 << 12)
#define TARGET_ACCOUNT      (1 << 13)
#define TARGET_CONNMARK     (1 << 14)
#define TARGET_TPROXY       (1 << 15)
#define TARGET_SETDNAT      (1 << 16)
#define TARGET_SETSNAT      (1 << 17)

static const struct ipt_entry ipt_targets[] = {
	{ "ACCEPT",     TARGET_ACCEPT },		/*  0 */
	{ "DROP",       TARGET_DROP },			/*  1 */
	{ "REJECT",     TARGET_REJECT },		/*  2 */
	{ "NOTRACK",    TARGET_NOTRACK },		/*  3 */
	{ "TCPMSS",     TARGET_TCPMSS },		/*  4 */
	{ "LOG",        TARGET_LOG },			/*  5 */
	{ "REDIRECT",   TARGET_REDIRECT },		/*  6 */
	{ "MASQUERADE", TARGET_MASQUERADE },		/*  7 */
	{ "MARK",       TARGET_MARK },			/*  8 */
	{ "DNAT",       TARGET_DNAT },			/*  9 */
	{ "SNAT",       TARGET_SNAT },			/* 10 */
	{ "CLASSIFY",   TARGET_CLASSIFY },		/* 11 */
	{ "SET",        TARGET_SET },			/* 12 */
	{ "ACCOUNT",    TARGET_ACCOUNT },		/* 13 */
	{ "CONNMARK",   TARGET_CONNMARK },		/* 14 */
	{ "TPROXY",     TARGET_TPROXY },		/* 15 */
	{ "SETDNAT",    TARGET_SETDNAT },		/* 16 */
	{ "SETSNAT",    TARGET_SETSNAT },		/* 17 */
};

static unsigned int ipt_target_flags = 0;

#define IF_TARGET_FLAG(flag) IF_FLAG(ipt_target_flags, flag, #flag)

#define MATCH_STATE         (1 <<  0)
#define MATCH_MULTIPORT     (1 <<  1)
#define MATCH_PKTTYPE       (1 <<  2)
#define MATCH_IPRANGE       (1 <<  3)
#define MATCH_MAC           (1 <<  4)
#define MATCH_MARK          (1 <<  5)
#define MATCH_LIMIT         (1 <<  6)
#define MATCH_TCP           (1 <<  7)
#define MATCH_UDP           (1 <<  8)
#define MATCH_ICMP          (1 <<  9)
#define MATCH_IPP2P         (1 << 10)
#define MATCH_SET           (1 << 11)
#define MATCH_SOCKET        (1 << 12)

static const struct ipt_entry ipt_matches[] = {
	{ "state",     MATCH_STATE },			/*  0 */
	{ "multiport", MATCH_MULTIPORT },		/*  1 */
	{ "pkttype",   MATCH_PKTTYPE },			/*  2 */
	{ "iprange",   MATCH_IPRANGE },			/*  3 */
	{ "mac",       MATCH_MAC },			/*  4 */
	{ "mark",      MATCH_MARK },			/*  5 */
	{ "limit",     MATCH_LIMIT },			/*  6 */
	{ "tcp",       MATCH_TCP },			/*  7 */
	{ "udp",       MATCH_UDP },			/*  8 */
	{ "icmp",      MATCH_ICMP },			/*  9 */
	{ "ipp2p",     MATCH_IPP2P },			/* 10 */
	{ "set",       MATCH_SET },			/* 11 */
	{ "socket",    MATCH_SOCKET },			/* 12 */
};

static unsigned int ipt_match_flags = 0;

#define IF_MATCH_FLAG(flag) IF_FLAG(ipt_match_flags, flag, #flag)

#define CHAIN_RAW           (1 <<  0)
#define CHAIN_NAT           (1 <<  1)
#define CHAIN_MANGLE        (1 <<  2)
#define CHAIN_FILTER        (1 <<  3)

static const struct ipt_entry ipt_chains[] = {
	{ "raw",    CHAIN_RAW },
	{ "nat",    CHAIN_NAT },
	{ "mangle", CHAIN_MANGLE },
	{ "filter", CHAIN_FILTER },
};

static unsigned int ipt_chain_flags = 0;

#define IF_CHAIN_FLAG(flag) IF_FLAG(ipt_chain_flags, flag)

/* Strip trailing CR/NL from string <s> */
#define chomp(s) ({ \
        char *c = (s) + strlen((s)) - 1; \
        while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
                *c-- = '\0'; \
        s; \
})

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}

static void ipt_init_dhcpfwd(const char *device, const char *ip)
{
	vasystem("iptables -A FORWARD -i %s -d %s -p udp --dport 67 -j ACCEPT", device, ip);
	vasystem("iptables -A FORWARD -i %s -p udp -s %s --sport 67 -j ACCEPT", device, ip);
	vasystem("iptables -A FORWARD -i %s -p udp --dport 67 -j DROP", device);

#if 0
	/* supress broadcast DHCP arriving at any LAN interface */
	/** VAR: InternetGatewayDevice.LANDevice.1.LANEthernetInterfaceConfig.1 */
	const char *vlan = get_if_device((tr069_selector){cwmp__InternetGatewayDevice,
							  cwmp__IGD_LANDevice,
							  1,
							  cwmp__IGD_LANDev_i_LANEthernetInterfaceConfig,
							  1, 0});
	if (vlan)
		vasystem("iptables -A INPUT -i %s -d 255.255.255.255 -p udp --dport 67 -j DROP", vlan);
#endif
}

void ipt_init(void)
{
	tr069_selector 	*sel, tmp = {cwmp__InternetGatewayDevice, cwmp__IGD_LANDevice, 0, cwmp__IGD_LANDev_i_LANHostConfigManagement, 0 ,0};
	const char	*lngldev, *fwdip;

	ENTER();

	if(!(sel = tr069_get_selector_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							cwmp__IGD_X_TPLINO_NET_NetworkGateway,
							cwmp__IGD_LNG_LANDevice, 0}))) {
		debug("(): could not retrieve LNG landevice.");
		EXIT();
		return;
	}

	tmp[2] = (*sel)[2];
	tmp[4] = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPRelay;

	/** VAR: InternetGatewayDevice.LANDevice.i.LANHostConfigManagement.DHCPRelay */
	if (tr069_get_bool_by_selector(tmp)) {
		/** VAR:InternetGatewayDevice.LANDevice.i.LANHostConfigManagement.X_TPOSS_DHCPForwardServer */
		tmp[4] = cwmp__IGD_LANDev_i_HostCfgMgt_X_TPOSS_DHCPForwardServer;
		fwdip = tr069_get_string_by_selector(tmp);

		/** VAR: InternetGatewayDevice.LANDevice.i */
		tmp[3] = 0; tmp[4] = 0; tmp[5] = 0;
		lngldev = get_if_device(tmp);
		debug("(): lngldev: %s, ip: %s", lngldev, fwdip);

		if (lngldev && fwdip)
			ipt_init_dhcpfwd(lngldev, fwdip);
	}

	EXIT();
	return;
}

void scg_acl_init()
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": No ACLs needed for LNG.");
}

void set_fw_wan_nat(tr069_id id)
{
	ENTER();

	if (fw_running && get_wan_nat(id)) {
		/* activate local WAN NAT exception rule */

		struct in_addr ip;

		ip = get_wan_ip(id);
		if (ip.s_addr != INADDR_ANY && ip.s_addr != INADDR_NONE) {
			char buf[INET_ADDRSTRLEN];

			vasystem("iptables -I TO_WAN_POSTR_LOCAL 1 -s %s -j ACCEPT", ip2str(ip, buf));
			vasystem("iptables -D TO_WAN_POSTR_LOCAL 2");
		}
	}

	EXIT();
}

void dm_proxy_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

// 	reload_proxy();
}

void dm_firewall_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	ipt_init();
}

void dm_scg_acl_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

// 	scg_acl_init();
}
