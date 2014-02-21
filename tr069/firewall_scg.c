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
#define TARGET_NFLOG        (1 << 18)
#define TARGET_NFQUEUE      (1 << 19)

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
	{ "NFLOG",      TARGET_NFLOG },			/* 18 */
	{ "NFQUEUE",    TARGET_NFQUEUE },		/* 19 */
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

static int get_ipt_flag(const struct ipt_entry entries[], size_t size, const char *name)
{
	for (unsigned int i = 0; i < size; i++) {
		debug("(): Comparing %s and %s\n", name, entries[i].name);
		if (strcasecmp(name, entries[i].name) == 0)
			return entries[i].flag;
	}
	return 0;
}

static int calc_flags(const char *fname, const struct ipt_entry entries[], size_t size)
{
	FILE *inf;
	char line[128];

	int flags = FLAG_DONE;

	inf = fopen(fname, "r");
	if (!inf)
		return flags;

	while (!feof(inf)) {
		if (!fgets(line, sizeof(line), inf))
			break;

		chomp(line);
		if (line[0] == '\0')
			break;

		flags |= get_ipt_flag(entries, size, line);
	}
	fclose(inf);
	debug("(): %s: flags: %x", fname, flags);

	return flags;
}

static void calc_target_flags(void)
{
	ipt_target_flags = calc_flags("/proc/net/ip_tables_targets",
				      ipt_targets,
				      sizeof(ipt_targets) / sizeof(struct ipt_entry));
}

static void calc_match_flags(void)
{
	ipt_match_flags = calc_flags("/proc/net/ip_tables_matches",
				     ipt_matches,
				     sizeof(ipt_matches) / sizeof(struct ipt_entry));
}

static void calc_chain_flags(void)
{
	ipt_chain_flags = calc_flags("/proc/net/ip_tables_names",
				     ipt_chains,
				     sizeof(ipt_chains) / sizeof(struct ipt_entry));
}

static const char *ipt_names[] = {
	[RAW]    = "raw",
	[MANGLE] = "mangle",
	[NAT]    = "nat",
	[FILTER] = "filter",
};

enum ipt_step {
	ROOT,
	TABLE,
	SCG_NAT,
	SCG_ZONE,
	SCG_ZONE_ACCNET,
	SCG_ZONE_AC,
	SCG_ZONE_END,
	CLOSE,
	IPT_STEP_MAX
};

typedef void ipt_cb(FILE *, struct tr069_instance_node *, const char *);
static void ipt_process(FILE *ipt, ipt_cb **cb)
{
	struct tr069_instance *l;
	struct tr069_instance_node *node;

	ENTER();

	if (!cb) {
		EXIT();
		return;
	}

	if (cb[ROOT])
		cb[ROOT](ipt, NULL, NULL);

	/** VAR: InternetGatewayDevice.LANDevice */
	l = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								 cwmp__IGD_LANDevice, 0 });
	if (!l) {
		EXIT();
		return;
	}

	debug("(): ipt_if_init: %p", cb[TABLE]);
	if (cb[TABLE])
		for (node = tr069_instance_first(l);
		     node != NULL;
		     node = tr069_instance_next(l, node)) {

			struct tr069_value_table *li = DM_TABLE(node->table);
			debug("(): got LANDevTable: %p", li);

			/** VAR: InternetGatewayDevice.LANDevice.{i} */
			const char *device = get_if_device((tr069_selector){cwmp__InternetGatewayDevice,
						cwmp__IGD_LANDevice,
						node->instance, 0 });

			if (!device)
				continue;

			cb[TABLE](ipt, node, device);
		}


	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool */
	debug("(): ipt_scg_nat_init: %p", cb[SCG_NAT]);
	if (cb[SCG_NAT]) {
		if ((l = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							cwmp__IGD_X_TPLINO_NET_SessionControl,
							cwmp__IGD_SCG_NATPool, 0 })))
			for (node = tr069_instance_first(l);
			     node != NULL;
			     node = tr069_instance_next(l, node))
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.Enabled */
				if (tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_NP_i_Enabled))
					cb[SCG_NAT](ipt, node, NULL);
	}

	if (cb[SCG_ZONE] || cb[SCG_ZONE_ACCNET] || cb[SCG_ZONE_AC] || cb[SCG_ZONE_END])
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
		if ((l = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							cwmp__IGD_X_TPLINO_NET_SessionControl,
							cwmp__IGD_SCG_Zone, 0 })))
			for (node = tr069_instance_first(l);
			     node != NULL;
			     node = tr069_instance_next(l, node)) {
				tr069_selector *ldev;

				/* TODO: notify on cwmp__IGD_SCG_Zone_i_Enabled */

				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
				if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Enabled))
					continue;

				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.LANDevice */
				ldev = tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_LANDevice);
				if (!ldev)
					continue;
				
				/** VAR: InternetGatewayDevice.LANDevice.{i} */
				const char *device = get_if_device(*ldev);
				if (!device)
					continue;

				debug("(): ipt_scg_zone_init: %p", cb[SCG_ZONE]);
				if (cb[SCG_ZONE])
					cb[SCG_ZONE](ipt, node, device);

				if (cb[SCG_ZONE_ACCNET]) {
					struct tr069_value_table *acs; 

					acs = tr069_get_table_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Accounting);
					if (acs) {
						struct tr069_instance *acc;
						struct tr069_instance_node *acc_node;
						
						if ((acc = tr069_get_instance_ref_by_id(acs, cwmp__IGD_SCG_Zone_i_Acc_SubNets)))
							for (acc_node = tr069_instance_first(acc);
							     acc_node != NULL;
							     acc_node = tr069_instance_next(acc, acc_node))
								cb[SCG_ZONE_ACCNET](ipt, acc_node, device);
					}
				}

				if (cb[SCG_ZONE_AC]) {
					struct tr069_value_table *acs; 

					acs = tr069_get_table_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_AccessClasses);
					if (acs) {
						struct tr069_instance *ac;
						struct tr069_instance_node *ac_node;
						
						if ((ac = tr069_get_instance_ref_by_id(acs, cwmp__IGD_SCG_Zone_i_ACs_AccessClass)))
							for (ac_node = tr069_instance_first(ac);
							     ac_node != NULL;
							     ac_node = tr069_instance_next(ac, ac_node))
								cb[SCG_ZONE_AC](ipt, ac_node, NULL);
					}
				}

				if (cb[SCG_ZONE_END])
					cb[SCG_ZONE_END](ipt, node, device);
			}

	if (cb[CLOSE])
		cb[CLOSE](ipt, NULL, NULL);

	EXIT();
}

typedef void pmap_cb(FILE *, int, struct tr069_instance_node *);
static void foreach_wan_pmap(FILE *ipt, int id, pmap_cb *cb)
{
	tr069_selector *map_sel;
	struct tr069_instance *pm;
	struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Enable */
	if (tr069_get_bool_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
						       cwmp__IGD_WANDevice,
						       id,
						       cwmp__IGD_WANDev_i_WANConnectionDevice,
						       1,
						       cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
						       1,
						       cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Enable, 0 }))
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.PortMapping */
		map_sel = &(tr069_selector){cwmp__InternetGatewayDevice,
					    cwmp__IGD_WANDevice,
					    id,
					    cwmp__IGD_WANDev_i_WANConnectionDevice,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_PortMapping, 0};

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.Enable */
	else if (tr069_get_bool_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							    cwmp__IGD_WANDevice,
							    id,
							    cwmp__IGD_WANDev_i_WANConnectionDevice,
							    1,
							    cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection,
							    1,
							    cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_Enable, 0}))
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.PortMapping */
		map_sel = &(tr069_selector){cwmp__InternetGatewayDevice,
					    cwmp__IGD_WANDevice,
					    id,
					    cwmp__IGD_WANDev_i_WANConnectionDevice,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PortMapping, 0};
	else {
		EXIT();
		return;
	}

	pm = tr069_get_instance_ref_by_selector(*map_sel);
	debug("(): got PMap: %p", pm);
	if (!pm) {
		EXIT();
		return;
	}

        for (node = tr069_instance_first(pm);
             node != NULL;
             node = tr069_instance_next(pm, node)) {
		struct tr069_value_table *pmi = DM_TABLE(node->table);
		debug("(): got PMap: %p", pmi);

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.PortMapping */
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.PortMapping */
		if (tr069_get_bool_by_id(pmi, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_PortMappingEnabled))
			cb(ipt, id, node);
	}
}

typedef void natmap_cb(FILE *, int, struct tr069_value_table *);
static void wan_natmap(FILE *ipt, int id, natmap_cb *cb)
{
	tr069_selector *map_sel;
	struct tr069_value_table *natp;

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Enable */
	if (tr069_get_bool_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
						       cwmp__IGD_WANDevice,
						       id,
						       cwmp__IGD_WANDev_i_WANConnectionDevice,
						       1,
						       cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
						       1,
						       cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Enable, 0 }))
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.X_TPLINO_NET_NATPool */
		map_sel = &(tr069_selector){cwmp__InternetGatewayDevice,
					    cwmp__IGD_WANDevice,
					    id,
					    cwmp__IGD_WANDev_i_WANConnectionDevice,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_X_TPLINO_NET_NATPool, 0};

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.Enable */
	else if (tr069_get_bool_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							    cwmp__IGD_WANDevice,
							    id,
							    cwmp__IGD_WANDev_i_WANConnectionDevice,
							    1,
							    cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection,
							    1,
							    cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_Enable, 0}))
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.X_TPLINO_NET_NATPool */
		map_sel = &(tr069_selector){cwmp__InternetGatewayDevice,
					    cwmp__IGD_WANDevice,
					    id,
					    cwmp__IGD_WANDev_i_WANConnectionDevice,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection,
					    1,
					    cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_X_TPLINO_NET_NATPool, 0};
	else {
		EXIT();
		return;
	}

	natp = tr069_get_table_by_selector(*map_sel);
	debug("(): got NATp: %p", natp);
	if (!natp) {
		EXIT();
		return;
	}

	if (tr069_get_bool_by_id(natp, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_NP_Enabled))
		cb(ipt, id, natp);
}

static void ipt_root_raw_table(FILE *ipt,
			       struct tr069_instance_node *vt __attribute__ ((unused)),
			       const char *device __attribute__ ((unused)))
{
	ENTER();

	/*
	 * create all raw tables
	 */
	fprintf(ipt,
		":PREROUTING ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n");

	EXIT();
}

static void ipt_root_mangle_table(FILE *ipt,
				  struct tr069_instance_node *vt __attribute__ ((unused)),
				  const char *device __attribute__ ((unused)))
{
	ENTER();

	/*
	 * create all mangle tables
	 */
	fprintf(ipt,
		":PREROUTING ACCEPT [0:0]\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":POSTROUTING ACCEPT [0:0]\n"
		":ACL_account - [0:0]\n");

	IF_TARGET_FLAG(TARGET_TPROXY)
		fprintf(ipt, ":DIVERT - [0:0]\n");
	EXIT();
}

static void ipt_if_mangle_table(FILE *ipt,
				struct tr069_instance_node *vt,
				const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = vt->instance;

	fprintf(ipt, ":LD_%d_PREROUTING - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_TO_LOCAL - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_POSTROUTING - [0:0]\n", id);
	fprintf(ipt, ":LOCAL_TO_LD_%d - [0:0]\n", id);
	fprintf(ipt, ":WAN_TO_LD_%d - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_TO_WAN - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_TO_LD_%d - [0:0]\n", id, id);

	EXIT();
}

static void ipt_scg_zone_mangle_table(FILE *ipt,
				      struct tr069_instance_node *zn,
				      const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = zn->instance;

	/*
	 * Gateway mangle tables
	 */
	fprintf(ipt, ":SCG_%d_PREROUTING - [0:0]\n", id);
	fprintf(ipt, ":SCG_%d_POSTROUTING - [0:0]\n", id);
	fprintf(ipt, ":ANY_TO_SCG_%d - [0:0]\n", id);
	fprintf(ipt, ":LOCAL_TO_SCG_%d - [0:0]\n", id);
	fprintf(ipt, ":SCG_%d_TO_ANY - [0:0]\n", id);
	fprintf(ipt, ":SCG_%d_TO_SCG_%d - [0:0]\n", id, id);

	EXIT();
}

static void ipt_scg_zone_ac_mangle_table(FILE *ipt __attribute__ ((unused)),
					 struct tr069_instance_node *ac,
					 const char *device __attribute__ ((unused)))
{
	ENTER();

	int zid = DM_TABLE(ac->table)->id[3];
	int id = ac->instance;

	fprintf(ipt, ":SCG_%d_AC_%d_in - [0:0]\n", zid, id);
	fprintf(ipt, ":SCG_%d_AC_%d_out - [0:0]\n", zid, id);

	vasystem("/usr/sbin/ipset -N SCG_%d_CLASSIFY_%d iphash", zid, id);

	EXIT();
}

static void ipt_root_mangle_setup(FILE *ipt __attribute__ ((unused)),
				  struct tr069_instance_node *vt __attribute__ ((unused)),
				  const char *device __attribute__ ((unused)))
{
	ENTER();

	/*
	 * PREROUTING
	 */
	IF_TARGET_FLAG(TARGET_TPROXY)
		fprintf(ipt, "-A PREROUTING -p tcp -m socket --transparent -j DIVERT\n");

	/*
	 * DIVERT
	 */
	IF_TARGET_FLAG(TARGET_TPROXY) {
		fprintf(ipt, "-A DIVERT -j MARK --set-mark 0x%x/0x%x\n", TPROXY_MARK(1), TPROXY_MASK);
		fprintf(ipt, "-A DIVERT -j ACCEPT\n");
	}

	/*
	 * TCPMSS
	 */
	IF_TARGET_FLAG(TARGET_TCPMSS)
		fprintf(ipt, "-A FORWARD -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n");

	EXIT();
}

static void ipt_if_mangle_setup(FILE *ipt,
				struct tr069_instance_node *vt,
				const char *device)
{
	ENTER();

	int id = vt->instance;

	if (!device) {
		debug("() didn't get device for LANDevice %d", id);
		EXIT();
		return;
	}

	const char *wan = get_wan_device(1);

	/*
	 * PREROUTING, attach chain
	 */
	fprintf(ipt, "-A PREROUTING -i %s -j LD_%d_PREROUTING\n", device, id);

	/*
	 * POSTROUTING, attach chain
	 */
	fprintf(ipt, "-A POSTROUTING -o %s -j LD_%d_POSTROUTING\n", device, id);

	/*
	 * local services for LD
	 */
	fprintf(ipt, "-A LD_%d_PREROUTING -j LD_%d_TO_LOCAL\n",  id, id);
	fprintf(ipt, "-A OUTPUT -o %s -j LOCAL_TO_LD_%d\n",  device, id);

	/*
	 * FORWARD
	 */
	if (wan) {
		fprintf(ipt, "-A FORWARD -i %s+ -o %s+ -j WAN_TO_LD_%d\n", wan, device, id);
		fprintf(ipt, "-A FORWARD -i %s+ -o %s+ -j LD_%d_TO_WAN\n", device, wan, id);
	}
	fprintf(ipt, "-A FORWARD -i %s -o %s -j LD_%d_TO_LD_%d\n", device, device, id, id);

	EXIT();
}

static void ipt_scg_zone_mangle_setup(FILE *ipt,
				      struct tr069_instance_node *zn,
				      const char *device __attribute__ ((unused)))
{
	tr069_selector *ldev;

	ENTER();

	int id = zn->instance;

	ldev = tr069_get_selector_by_id(DM_TABLE(zn->table), cwmp__IGD_SCG_Zone_i_LANDevice);

	/*
	 * Zone marking
	 */
	fprintf(ipt, "-A SCG_%d_PREROUTING -j MARK --set-mark 0x%x/0x%x\n",
		id, scg_mark(zn->idm, 0, 0, 0), SCG_POS_MASK_ZONE);
	fprintf(ipt, "-A SCG_%d_POSTROUTING -j MARK --set-mark 0x%x/0x%x\n",
		id, scg_mark(zn->idm, 0, 0, 0), SCG_POS_MASK_ZONE);
	fprintf(ipt, "-A LOCAL_TO_SCG_%d -j MARK --set-mark 0x%x/0x%x\n",
		id, scg_mark(zn->idm, 0, 0, 0), SCG_POS_MASK_ZONE);
	fprintf(ipt, "-A ANY_TO_SCG_%d -j MARK --set-mark 0x%x/0x%x\n",
		id, scg_mark(zn->idm, 0, 0, 0), SCG_POS_MASK_ZONE);

	/*
	 * attach Zone to PRE/POST ROUTING
	 */
	fprintf(ipt, "-A LD_%d_PREROUTING -j SCG_%d_PREROUTING\n",  (*ldev)[2], id);
	fprintf(ipt, "-A LD_%d_POSTROUTING -j SCG_%d_POSTROUTING\n",  (*ldev)[2], id);

	/*
	 * attach Zone to FORWARD
	 */
	fprintf(ipt, "-A WAN_TO_LD_%d -j ANY_TO_SCG_%d\n",  (*ldev)[2], id);
	fprintf(ipt, "-A LOCAL_TO_LD_%d -j LOCAL_TO_SCG_%d\n",  (*ldev)[2], id);
	fprintf(ipt, "-A LD_%d_TO_WAN -j SCG_%d_TO_ANY\n",  (*ldev)[2], id);

	/*
	 * SCG to SCG
	 */
	fprintf(ipt, "-A LD_%d_TO_LD_%d -j SCG_%d_TO_SCG_%d\n",  (*ldev)[2], (*ldev)[2], id, id);
	fprintf(ipt, "-A SCG_%d_TO_SCG_%d -j ANY_TO_SCG_%d\n", id, id, id);
	fprintf(ipt, "-A SCG_%d_TO_SCG_%d -j SCG_%d_TO_ANY\n", id, id, id);

	EXIT();
}

static void ipt_scg_accnet_mangle_setup(FILE *ipt,
					struct tr069_instance_node *net,
					const char *device __attribute__ ((unused)))
{
	char buf[INET_ADDRSTRLEN];
	unsigned int prefixlen;
	const char *ip = NULL;

	ENTER();

	int zid = DM_TABLE(net->table)->id[3];
	int id = net->instance;

	ip = ip2str(tr069_get_ipv4_by_id(DM_TABLE(net->table), cwmp__IGD_SCG_Zone_i_Acc_SN_j_Network), buf);
	prefixlen = tr069_get_uint_by_id(DM_TABLE(net->table), cwmp__IGD_SCG_Zone_i_Acc_SN_j_PrefixLen);

	debug(": Id: %d, IP: %s, PrefixLen: %d", id, ip ? ip : "NULL", prefixlen);

	IF_TARGET_FLAG(TARGET_ACCOUNT)
		if (ip && prefixlen >= 8 && prefixlen < 32)
			fprintf(ipt, "-A ACL_account -j ACCOUNT --addr %s/%d --tname account_%d_%d\n", ip, prefixlen, zid, id);

	EXIT();
}

static void ipt_scg_zone_ac_mangle_setup(FILE *ipt,
					 struct tr069_instance_node *ac,
					 const char *device __attribute__ ((unused)))
{
	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	int id = ac->instance;
	struct tr069_value_table *ac_t = DM_TABLE(ac->table);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	int zid = ac_t->id[3];

	/* SCG to any */
	fprintf(ipt, "-A SCG_%d_PREROUTING -m set --set SCG_%d_CLASSIFY_%d src -j SCG_%d_AC_%d_out\n", zid, zid, id, zid, id);

	/* any to SCG */
	fprintf(ipt, "-A LOCAL_TO_SCG_%d -m set --set SCG_%d_CLASSIFY_%d dst -j SCG_%d_AC_%d_in\n", zid, zid, id, zid, id);
	fprintf(ipt, "-A ANY_TO_SCG_%d -m set --set SCG_%d_CLASSIFY_%d dst -j SCG_%d_AC_%d_in\n", zid, zid, id, zid, id);

	/*
	 * marks in PREROUTING in chain - SCG to WAN
	 * (mark unconditionally to fix the mark of packets reinjected by sol-triggerd)
	 */
	fprintf(ipt, "-A SCG_%d_AC_%d_out -j MARK --set-mark 0x%x/0x%x\n",
		zid, id, scg_mark(0, ac->idm, 0, 0), SCG_POS_MASK_ACCESSCLASS);

	/* marks in PREROUTING in chain - WAN to SCG */
	fprintf(ipt, "-A SCG_%d_AC_%d_in -m mark --mark 0x0/0x%x -j MARK --set-mark 0x%x/0x%x\n",
		zid, id, SCG_POS_MASK_ACCESSCLASS, scg_mark(0, ac->idm, 0, 0), SCG_POS_MASK_ACCESSCLASS);

	/*
	 * final verdict - account everything else
	 */
	fprintf(ipt, "-A SCG_%d_AC_%d_in -j ACL_account\n", zid, id);
	fprintf(ipt, "-A SCG_%d_AC_%d_out -j ACL_account\n", zid, id);

	EXIT();
}

static void ipt_scg_zone_end_mangle_setup(FILE *ipt,
					  struct tr069_instance_node *zn,
					  const char *device __attribute__ ((unused)))
{
	tr069_selector *unk;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	int id = zn->instance;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.UnknownAccessClass */
	unk = tr069_get_selector_by_id(DM_TABLE(zn->table), cwmp__IGD_SCG_Zone_i_UnknownAccessClass);
	if (unk) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
		int acid = (*unk)[6];

		/* outgoing SCG to any */
		fprintf(ipt, "-A SCG_%d_PREROUTING -j SCG_%d_AC_%d_out\n", id, id, acid);

		/* incoming any to SCG */
		fprintf(ipt, "-A ANY_TO_SCG_%d -m mark --mark 0x0/0x%x -j SCG_%d_AC_%d_in\n", id, SCG_POS_MASK_ACCESSCLASS, id, acid);
		fprintf(ipt, "-A LOCAL_TO_SCG_%d -m mark --mark 0x0/0x%x -j SCG_%d_AC_%d_in\n", id, SCG_POS_MASK_ACCESSCLASS, id, acid);
	}

	EXIT();
}

static void ipt_close_mangle_setup(FILE *ipt,
				   struct tr069_instance_node *vt __attribute__ ((unused)),
				   const char *device __attribute__ ((unused)))
{
	ENTER();

	fprintf(ipt, "-A ACL_account -j ACCEPT\n");

	EXIT();
}

static void ipt_root_nat_table(FILE *ipt,
			       struct tr069_instance_node *vt __attribute__ ((unused)),
			       const char *device __attribute__ ((unused)))
{
	ENTER();

	/*
	 * create all nat tables
	 */
	fprintf(ipt,
		":PREROUTING ACCEPT [0:0]\n"
		":POSTROUTING ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":FROM_WAN_PREROUTING - [0:0]\n"
		":TO_WAN_POSTR_LOCAL - [0:0]\n"
		":TO_WAN_POSTROUTING - [0:0]\n");

	IF_NOT_FLAG(ipt_target_flags, TARGET_TPROXY)
		fprintf(ipt, ":SCG_REDIRECT - [0:0]\n");

	EXIT();
}

static void ipt_if_nat_table(FILE *ipt,
			     struct tr069_instance_node *vt,
			     const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = vt->instance;

	fprintf(ipt, ":LD_%d_PREROUTING - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_OUTPUT - [0:0]\n", id);

	EXIT();
}

static void ipt_scg_nat_nat_table(FILE *ipt,
				  struct tr069_instance_node *nat,
				  const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = nat->instance;

	fprintf(ipt, ":NATP_%d_PREROUTING - [0:0]\n", id);
	fprintf(ipt, ":NATP_%d_POSTROUTING - [0:0]\n", id);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.Translation */
	switch (tr069_get_enum_by_id(DM_TABLE(nat->table), cwmp__IGD_SCG_NP_i_Translation)) {
	case cwmp___IGD_SCG_NP_i_Translation_SymetricAddressKeyed:
		vasystem("/usr/sbin/ipset -N DNATP_%d iphash_nat", id);

	case cwmp___IGD_SCG_NP_i_Translation_AddressKeyed:
	case cwmp___IGD_SCG_NP_i_Translation_PortKeyed:
		vasystem("/usr/sbin/ipset -N SNATP_%d iphash_nat", id);
		break;

	case cwmp___IGD_SCG_NP_i_Translation_Random:
	case cwmp___IGD_SCG_NP_i_Translation_RandomPersistent:
	case cwmp___IGD_SCG_NP_i_Translation_Masquerade:
		break;

	default:
		debug("unsupported NAT translation in instance %d", id);
		break;
	}

	EXIT();
}

static void ipt_scg_zone_nat_table(FILE *ipt,
				   struct tr069_instance_node *zn,
				   const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = zn->instance;

	/*
	 * Gateway NAT/Redirect tables
	 */
	fprintf(ipt, ":SCG_%d_PREROUTING - [0:0]\n", id);
	fprintf(ipt, ":SCG_%d_POSTROUTING - [0:0]\n", id);

	EXIT();
}

static void ipt_scg_zone_ac_nat_table(FILE *ipt,
				      struct tr069_instance_node *ac,
				      const char *device __attribute__ ((unused)))
{
	ENTER();

	int zid = DM_TABLE(ac->table)->id[3];
	int id = ac->instance;

	fprintf(ipt, ":SCG_%d_AC_%d_out - [0:0]\n", zid, id);

	EXIT();
}

static void ipt_root_nat_setup(FILE *ipt,
			       struct tr069_instance_node *vt __attribute__ ((unused)),
			       const char *device __attribute__ ((unused)))
{
	ENTER();

	IF_NOT_FLAG(ipt_target_flags, TARGET_TPROXY) {
		fprintf(ipt, "-A SCG_REDIRECT -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128\n");
	}

	EXIT();
}

static void ipt_if_nat_setup(FILE *ipt,
			     struct tr069_instance_node *vt,
			     const char *device)
{
	ENTER();

	int id = vt->instance;

	if (!device) {
		debug("() didn't get device for LANDevice %d", id);
		EXIT();
		return;
	}

	/* attache all LANDevice.{i} rules */
	fprintf(ipt, "-A PREROUTING -i %s -j LD_%d_PREROUTING\n", device, id);
	fprintf(ipt, "-A OUTPUT -o %s -j LD_%d_OUTPUT\n", device, id);

	EXIT();
}

static void ipt_scg_nat_nat_setup(FILE *ipt,
				  struct tr069_instance_node *nat,
				  const char *device __attribute__ ((unused)))
{
	int id = nat->instance;
	int transl;
	const char *persist = "";
	char port[13] = "\0\0";
	unsigned int min = 0;
	unsigned int max = 0;
	char minbuf[INET_ADDRSTRLEN] = "";
	char maxbuf[INET_ADDRSTRLEN+1] = "";
	struct in_addr min_ip;
	struct in_addr max_ip;

	ENTER();

	fprintf(ipt, "-A PREROUTING -j NATP_%d_PREROUTING\n", id);
	fprintf(ipt, "-A POSTROUTING -j NATP_%d_POSTROUTING\n", id);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.Translation */
	transl =tr069_get_enum_by_id(DM_TABLE(nat->table), cwmp__IGD_SCG_NP_i_Translation);
	switch (transl) {
	case cwmp___IGD_SCG_NP_i_Translation_RandomPersistent:
	case cwmp___IGD_SCG_NP_i_Translation_Random:
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.MinAddress */
		min_ip = tr069_get_ipv4_by_id(DM_TABLE(nat->table), cwmp__IGD_SCG_NP_i_MinAddress);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.MaxAddress */
		max_ip = tr069_get_ipv4_by_id(DM_TABLE(nat->table), cwmp__IGD_SCG_NP_i_MaxAddress);

		if (min_ip.s_addr == INADDR_ANY || min_ip.s_addr == INADDR_NONE)
			break;
		ip2str(min_ip, minbuf);

		if (max_ip.s_addr != INADDR_ANY && max_ip.s_addr != INADDR_NONE) {
			maxbuf[0] = '-';
			ip2str(max_ip, &maxbuf[1]);
		} else
			maxbuf[0] = '\0';

		/* FALL THROUGH */
	case cwmp___IGD_SCG_NP_i_Translation_Masquerade:
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.MinPort */
		min = tr069_get_uint_by_id(DM_TABLE(nat->table), cwmp__IGD_SCG_NP_i_MinPort);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.MaxPort */
		max = tr069_get_uint_by_id(DM_TABLE(nat->table), cwmp__IGD_SCG_NP_i_MaxPort);

		if (min != 0) {
			if (min < 1024)
				min = 1024;
			else if (min > 65535)
				min = 65535;
		}

		if (max != 0) {
			if (min == 0)
				min = 1024;
			if (max < 1024)
				max = 1024;
			else if (max > 65535)
				max = 65535;
		}
		if (max < min)
			max = min;

		if (min || max)
			snprintf(port, sizeof(port), ":%u-%u", min, max);
		else
			port[0] = '\0';
		break;

	default:
		break;
	}

	switch (transl) {
	case cwmp___IGD_SCG_NP_i_Translation_SymetricAddressKeyed:
		IF_TARGET_FLAG(TARGET_SETDNAT)
			fprintf(ipt, "-A NATP_%d_PREROUTING -m set --set DNATP_%d dst -j SETDNAT --setdnat DNATP_%d\n", id, id, id);

		/* FALL THROUGH */
	case cwmp___IGD_SCG_NP_i_Translation_AddressKeyed:
	case cwmp___IGD_SCG_NP_i_Translation_PortKeyed:
		IF_TARGET_FLAG(TARGET_SETSNAT)
			fprintf(ipt, "-A NATP_%d_POSTROUTING -m set --set SNATP_%d src -j SETSNAT --setsnat SNATP_%d\n", id, id, id);
		break;

	case cwmp___IGD_SCG_NP_i_Translation_RandomPersistent:
		persist = " --persistent";

		/* FALL THROUGH */
	case cwmp___IGD_SCG_NP_i_Translation_Random:
		IF_TARGET_FLAG(TARGET_SNAT) {
			if (min || max) {
				fprintf(ipt, "-A NATP_%d_POSTROUTING -p tcp -j SNAT --to-source %s%s%s --random%s\n", id, minbuf, maxbuf, port, persist);
				fprintf(ipt, "-A NATP_%d_POSTROUTING -p udp -j SNAT --to-source %s%s%s --random%s\n", id, minbuf, maxbuf, port, persist);
			}
			fprintf(ipt, "-A NATP_%d_POSTROUTING -j SNAT --to-source %s%s --random%s\n", id, minbuf, maxbuf, persist);
		}
		break;

	case cwmp___IGD_SCG_NP_i_Translation_Masquerade:
		IF_TARGET_FLAG(TARGET_MASQUERADE) {
			if (min || max) {
				fprintf(ipt, "-A NATP_%d_POSTROUTING -p tcp -j MASQUERADE --to-ports %u-%u --random\n", id, min, max);
				fprintf(ipt, "-A NATP_%d_POSTROUTING -p udp -j MASQUERADE --to-ports %u-%u --random\n", id, min, max);
			}
			fprintf(ipt, "-A NATP_%d_POSTROUTING -j MASQUERADE --random\n", id);
		}
		break;

	default:
		debug("unsupported NAT translation in instance %d", id);
		break;
	}

	EXIT();
}

static void ipt_scg_zone_nat_setup(FILE *ipt, struct tr069_instance_node *zn, const char *device __attribute__ ((unused)))
{
	tr069_selector *ldev;

	ENTER();

	debug("(): zn: %p\n", zn);
	int id = zn->instance;

	ldev = tr069_get_selector_by_id(DM_TABLE(zn->table), cwmp__IGD_SCG_Zone_i_LANDevice);

	/*
	 * Assign links and rules to these new chains
	 */
	fprintf(ipt, "-A LD_%d_PREROUTING -m mark --mark 0x%x/0x%x -j SCG_%d_PREROUTING\n",
		(*ldev)[2], scg_mark(zn->idm, 0, 0, 0), SCG_POS_MASK_ZONE, id);

	/*
	 * mark based filtering does not work for traffic from the local proxy
	 *
	fprintf(ipt, "-A POSTROUTING -m mark --mark 0x%x/0x%x -j SCG_%d_POSTROUTING\n",
		scg_mark(zn->idm, 0, 0, 0), SCG_POS_MASK_ZONE, id);
	*/
	fprintf(ipt, "-A POSTROUTING -j SCG_%d_POSTROUTING\n", id);

	IF_NOT_FLAG(ipt_target_flags, TARGET_TPROXY) {
		fprintf(ipt, "-A SCG_%d_PREROUTING -m mark --mark 0x%x/0x%x -j SCG_REDIRECT\n", id, TPROXY_MARK(1), TPROXY_MASK);
	}

	EXIT();
}

static void ipt_scg_zone_ac_nat_setup(FILE *ipt,
				      struct tr069_instance_node *ac,
				      const char *device __attribute__ ((unused)))
{
	ENTER();

	int zid = DM_TABLE(ac->table)->id[3];
	int id = ac->instance;

	/*
	 * SCG to WAN
	 */
	fprintf(ipt, "-A SCG_%d_PREROUTING -m mark --mark 0x%x/0x%x -j SCG_%d_AC_%d_out\n",
		zid, scg_mark(0, ac->idm, 0, 0), SCG_POS_MASK_ACCESSCLASS, zid, id);

	EXIT();
}

static void ipt_close_nat_wan_portmapping(FILE *ipt,
					  int id  __attribute__ ((unused)),
					  struct tr069_instance_node *node)
{
	struct tr069_value_table *pm = DM_TABLE(node->table);

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.PortMappingProtocol */
	int proto = tr069_get_enum_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_PortMappingProtocol);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.ExternalPort */
	int eport = tr069_get_int_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_ExternalPort);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.InternalPort */
	int iport = tr069_get_int_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_InternalPort);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.InternalClient */
	const char *ihost = tr069_get_string_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_InternalClient);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.RemoteHost */
	const char *rhost = tr069_get_string_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_RemoteHost);

	if (!ihost || !*ihost) {
		EXIT();
		return;
	}

	if (rhost && *rhost)
		fprintf(ipt, "-A FROM_WAN_PREROUTING -p %s -s %s --dport %d -j DNAT --to %s:%d\n",
			proto_names[proto], rhost, eport, ihost, iport);
	else
		fprintf(ipt, "-A FROM_WAN_PREROUTING -p %s --dport %d -j DNAT --to %s:%d\n",
			proto_names[proto], eport, ihost, iport);

	EXIT();
}

static void ipt_close_nat_wan_natpool(FILE *ipt,
				      int id  __attribute__ ((unused)),
				      struct tr069_value_table *natp)
{
	char minbuf[INET_ADDRSTRLEN];
	char maxbuf[INET_ADDRSTRLEN];

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.X_TPLINO_NET_NATPool.MinAddress */
	struct in_addr min = tr069_get_ipv4_by_id(natp, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_NP_MinAddress);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.X_TPLINO_NET_NATPool.MaxAddress */
	struct in_addr max = tr069_get_ipv4_by_id(natp, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_NP_MaxAddress);

	if (min.s_addr == INADDR_ANY || min.s_addr == INADDR_NONE ||
	    max.s_addr == INADDR_ANY || max.s_addr == INADDR_NONE) {
		EXIT();
		return;
	}

	fprintf(ipt, "-A TO_WAN_POSTROUTING -j SNAT --to-source %s-%s --random\n",
		ip2str(min, minbuf), ip2str(max, maxbuf));

	EXIT();
}

static void ipt_close_nat_setup(FILE *ipt,
				struct tr069_instance_node *vt __attribute__ ((unused)),
				const char *device __attribute__ ((unused)))
{
	ENTER();

	/*
	 * masquerading
	 */

	const char *wan = get_wan_device(1);
	if (wan) {
		/* attach WAN routing hooks */
		fprintf(ipt, "-A PREROUTING -i %s -j FROM_WAN_PREROUTING\n", wan);
		fprintf(ipt, "-A POSTROUTING -o %s -j TO_WAN_POSTROUTING\n", wan);
	}

	/*
	 * preroutings
	 */
	foreach_wan_pmap(ipt, 1, ipt_close_nat_wan_portmapping);

	/*
	 * postroutings
	 */
	if (get_wan_nat(1)) {
		struct in_addr ip;

		fprintf(ipt, "-A TO_WAN_POSTROUTING -j TO_WAN_POSTR_LOCAL\n");
		wan_natmap(ipt, 1, ipt_close_nat_wan_natpool);
		fprintf(ipt, "-A TO_WAN_POSTROUTING -j MASQUERADE\n");

		ip = get_wan_ip(1);
		if (ip.s_addr != INADDR_ANY && ip.s_addr != INADDR_NONE) {
			char buf[INET_ADDRSTRLEN];

			fprintf(ipt, "-A TO_WAN_POSTR_LOCAL -s %s -j ACCEPT\n", ip2str(ip, buf));
		}
	}

	EXIT();
}

static void ipt_root_filter_table(FILE *ipt,
				  struct tr069_instance_node *vt __attribute__ ((unused)),
				  const char *device __attribute__ ((unused)))
{
	ENTER();

	/*
	 * create all filter tables
	 */
	fprintf(ipt,
		":INPUT ACCEPT [0:0]\n"
		":FORWARD DROP [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":DENY - [0:0]\n");

	EXIT();
}

static void ipt_if_filter_table(FILE *ipt,
				struct tr069_instance_node *vt,
				const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = vt->instance;

	fprintf(ipt, ":LD_%d_INPUT - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_OUTPUT - [0:0]\n", id);
	fprintf(ipt, ":WAN_TO_LD_%d - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_TO_WAN - [0:0]\n", id);
	fprintf(ipt, ":LD_%d_TO_LD_%d - [0:0]\n", id, id);

	EXIT();
}

static void ipt_scg_zone_filter_table(FILE *ipt,
				      struct tr069_instance_node *zn,
				      const char *device __attribute__ ((unused)))
{
	ENTER();

	int id = zn->instance;

	fprintf(ipt, ":ANY_TO_SCG_%d - [0:0]\n", id);
	fprintf(ipt, ":SCG_%d_TO_ANY - [0:0]\n", id);
	fprintf(ipt, ":SCG_%d_TO_SCG_%d - [0:0]\n", id, id);

	EXIT();
}

static void ipt_scg_zone_ac_filter_table(FILE *ipt __attribute__ ((unused)),
					 struct tr069_instance_node *ac,
					 const char *device __attribute__ ((unused)))
{
	ENTER();

	int zid = DM_TABLE(ac->table)->id[3];
	int id = ac->instance;

	fprintf(ipt, ":SCG_%d_AC_%d_in - [0:0]\n", zid, id);
	fprintf(ipt, ":SCG_%d_AC_%d_out - [0:0]\n", zid, id);

	EXIT();
}

#if 0
static void ipt_root_filter_wan_input(FILE *ipt,
				      int id __attribute__ ((unused)),
				      const char *wan,
				      struct tr069_instance_node *node)
{
	ENTER();

#if 0
	struct tr069_value_table *pm = DM_TABLE(node->table);

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.PortMappingProtocol */
	int proto = tr069_get_enum_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_PortMappingProtocol);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.ExternalPort */
	int dport = tr069_get_int_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_ExternalPort);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.RemoteHost */
	const char *rhost = tr069_get_string_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_RemoteHost);

	if (rhost && *rhost)
		fprintf(ipt, "-A INPUT -i %s -p %s -s %s --dport %d -j ACCEPT\n",
			wan, proto_names[proto], rhost, dport);
	else
		fprintf(ipt, "-A INPUT -i %s -p %s --dport %d -j ACCEPT\n",
			wan, proto_names[proto], dport);
#endif

	EXIT();
}

static void ipt_root_filter_wan_forward(FILE *ipt,
					int id __attribute__ ((unused)),
					const char *wan,
					struct tr069_instance_node *node)
{
	ENTER();

#if 0
	struct tr069_value_table *pm = DM_TABLE(node->table);

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.PortMappingProtocol */
	int proto = tr069_get_enum_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_PortMappingProtocol);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.InternalPort */
	int dport = tr069_get_int_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_InternalPort);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.InternalClient */
	const char *ihost =  tr069_get_string_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_InternalClient);
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANxxxConnection.{i}.PortMapping.{i}.RemoteHost */
	const char *rhost =  tr069_get_string_by_id(pm, cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_PMap_l_RemoteHost);

	if (!ihost || !*ihost) {
		EXIT();
		return;
	}

	if (rhost && *rhost)
		fprintf(ipt, "-A FORWARD -i+ %s -p %s -s %s -d %s --dport %d -j ACCEPT\n",
			wan, proto_names[proto], rhost, ihost, dport);
	else
		fprintf(ipt, "-A FORWARD -i+ %s -p %s -d %s --dport %d -j ACCEPT\n",
			wan, proto_names[proto], ihost, dport);
#endif
	EXIT();
}
#endif

static void ipt_root_filter_setup(FILE *ipt,
				  struct tr069_instance_node *vt __attribute__ ((unused)),
				  const char *device __attribute__ ((unused)))
{
	ENTER();

	fprintf(ipt, "-A FORWARD -m state --state INVALID -j DROP\n");
	fprintf(ipt, "-A DENY -p tcp -j REJECT --reject-with tcp-reset\n");
	fprintf(ipt, "-A DENY -j REJECT --reject-with icmp-admin-prohibited\n");

	EXIT();
}

static void ipt_if_filter_setup(FILE *ipt,
				struct tr069_instance_node *vt,
				const char *device)
{
	struct tr069_value_table *hcfg;

	ENTER();

	int id = vt->instance;
	if (!device) {
		debug("() didn't get device for LANDevice %d", id);
		EXIT();
		return;
	}

	const char *wan = get_wan_device(1);

	if (wan) {
		fprintf(ipt, "-A FORWARD -i %s+ -o %s+ -j WAN_TO_LD_%d\n", wan, device, id);
		fprintf(ipt, "-A FORWARD -i %s+ -o %s+ -j LD_%d_TO_WAN\n", device, wan, id);
	}
	fprintf(ipt, "-A FORWARD -i %s -o %s -j LD_%d_TO_LD_%d\n", device, device, id, id);

	hcfg = tr069_get_table_by_id(DM_TABLE(vt->table), cwmp__IGD_LANDev_i_LANHostConfigManagement);
	if (hcfg) {
		unsigned int limit, burst;

		limit = tr069_get_uint_by_id(hcfg, cwmp__IGD_LANDev_i_HostCfgMgt_X_TPLINO_NET_DHCPLimitRate);
		burst = tr069_get_uint_by_id(hcfg, cwmp__IGD_LANDev_i_HostCfgMgt_X_TPLINO_NET_DHCPLimitBurst);

		if (limit != 0) {
			if (burst == 0)
				burst = limit / 4;
			if (burst == 0)
				burst = 1;

			fprintf(ipt, "-A LD_%d_INPUT -p udp --dport 67 -m limit --limit %d/second --limit-burst %d -j ACCEPT\n", id, limit, burst);
			fprintf(ipt, "-A LD_%d_INPUT -p udp --dport 67 -j DROP\n", id);

			fprintf(ipt, "-A INPUT -i %s -j LD_%d_INPUT\n", device, id);
		}
	}
#if 0
	fprintf(ipt, "-A OUTPUT -o %s -j LD_%d_OUTPUT\n", device, id);
#endif

	EXIT();
}

static void ipt_scg_zone_filter_setup(FILE *ipt,
				      struct tr069_instance_node *zn,
				      const char *device __attribute__ ((unused)))
{
	tr069_selector *ldev;

	ENTER();

	int id = zn->instance;

	/*
	 * attach Zone to FORWARD
	 */
	ldev = tr069_get_selector_by_id(DM_TABLE(zn->table), cwmp__IGD_SCG_Zone_i_LANDevice);

	/*
	 * WAN to SCG
	 */
	fprintf(ipt, "-A WAN_TO_LD_%d -j ANY_TO_SCG_%d\n",  (*ldev)[2], id);

	/*
	 * SCG to WAN
	 */
	fprintf(ipt, "-A LD_%d_TO_WAN -j SCG_%d_TO_ANY\n",  (*ldev)[2], id);

	/*
	 * SCG to SCG
	 */
	fprintf(ipt, "-A LD_%d_TO_LD_%d -j SCG_%d_TO_SCG_%d\n",  (*ldev)[2], (*ldev)[2], id, id);
	fprintf(ipt, "-A SCG_%d_TO_SCG_%d -j ANY_TO_SCG_%d\n", id, id, id);
	fprintf(ipt, "-A SCG_%d_TO_SCG_%d -j SCG_%d_TO_ANY\n", id, id, id);

	EXIT();
}

static void ipt_scg_zone_ac_filter_setup(FILE *ipt,
					 struct tr069_instance_node *ac,
					 const char *device __attribute__ ((unused)))
{
	ENTER();

	int zid = DM_TABLE(ac->table)->id[3];
	int id = ac->instance;

	/* SCG to WAN */
	fprintf(ipt, "-A SCG_%d_TO_ANY -m mark --mark 0x%x/0x%x -j SCG_%d_AC_%d_out\n",
		zid, scg_mark(0, ac->idm, 0, 0), SCG_POS_MASK_ACCESSCLASS, zid, id);

	/* WAN to SCG */
	fprintf(ipt, "-A ANY_TO_SCG_%d -m mark --mark %d/0x%x -j SCG_%d_AC_%d_in\n",
		zid, scg_mark(0, ac->idm, 0, 0), SCG_POS_MASK_ACCESSCLASS, zid, id);

	/*
	 * final verdict - accept everything else
	 */
	fprintf(ipt, "-A SCG_%d_AC_%d_in -j ACCEPT\n", zid, id);
	fprintf(ipt, "-A SCG_%d_AC_%d_out -j ACCEPT\n", zid, id);

	EXIT();
}

static void ipt_scg_zone_end_filter_setup(FILE *ipt,
					  struct tr069_instance_node *zn,
					  const char *device __attribute__ ((unused)))
{
	tr069_selector *ldev;

	ENTER();

	ldev = tr069_get_selector_by_id(DM_TABLE(zn->table), cwmp__IGD_SCG_Zone_i_LANDevice);

#if 0
	/*
	 * WAN to SCG
	 */
	fprintf(ipt, "-A ANY_TO_SCG_%d -m mark ! --mark 0 -j ACCEPT\n",  id);

	/*
	 * SCG to WAN
	 */
	fprintf(ipt, "-A SCG_%d_TO_ANY -m mark ! --mark 0 -j ACCEPT\n",  id);
#endif

	fprintf(ipt, "-A WAN_TO_LD_%d -m state --state RELATED,ESTABLISHED -j ACCEPT\n", (*ldev)[2]);

	EXIT();
}

static void ipt_close_filter_setup(FILE *ipt,
				   struct tr069_instance_node *vt __attribute__ ((unused)),
				   const char *device __attribute__ ((unused)))
{
	ENTER();

	fprintf(ipt, "-A FORWARD -m state --state INVALID,NEW -j DROP\n");

	EXIT();
}

static ipt_cb *ipt_init_tab[IPT_TYPE_MAX][IPT_STEP_MAX] = {
	[RAW]     = { [ROOT]		= ipt_root_raw_table,
		      [TABLE]		= NULL,
		      [SCG_NAT]		= NULL,
		      [SCG_ZONE]	= NULL,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= NULL,
		      [SCG_ZONE_END]	= NULL,
		      [CLOSE]		= NULL,
	},

	[MANGLE]  = { [ROOT]		= ipt_root_mangle_table,
		      [TABLE]		= ipt_if_mangle_table,
		      [SCG_NAT]		= NULL,
		      [SCG_ZONE]	= ipt_scg_zone_mangle_table,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= ipt_scg_zone_ac_mangle_table,
		      [SCG_ZONE_END]	= NULL,
		      [CLOSE]		= NULL,
	},

	[NAT]     = { [ROOT]		= ipt_root_nat_table,
		      [TABLE]		= ipt_if_nat_table,
		      [SCG_NAT]		= ipt_scg_nat_nat_table,
		      [SCG_ZONE]	= ipt_scg_zone_nat_table,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= ipt_scg_zone_ac_nat_table,
		      [SCG_ZONE_END]	= NULL,
		      [CLOSE]		= NULL,
	},

	[FILTER]  = { [ROOT]		= ipt_root_filter_table,
		      [TABLE]		= ipt_if_filter_table,
		      [SCG_NAT]		= NULL,
		      [SCG_ZONE]	= ipt_scg_zone_filter_table,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= ipt_scg_zone_ac_filter_table,
		      [SCG_ZONE_END]	= NULL,
		      [CLOSE]		= NULL,
	},
};

static ipt_cb *ipt_setup_tab[IPT_TYPE_MAX][IPT_STEP_MAX] = {
	[RAW]     = { [ROOT]		= NULL,
		      [TABLE]		= NULL,
		      [SCG_NAT]		= NULL,
		      [SCG_ZONE]	= NULL,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= NULL,
		      [SCG_ZONE_END]	= NULL,
		      [CLOSE]		= NULL,
	},

	[MANGLE]  = { [ROOT]		= ipt_root_mangle_setup,
		      [TABLE]		= ipt_if_mangle_setup,
		      [SCG_NAT]		= NULL,
		      [SCG_ZONE]	= ipt_scg_zone_mangle_setup,
		      [SCG_ZONE_ACCNET]	= ipt_scg_accnet_mangle_setup,
		      [SCG_ZONE_AC]	= ipt_scg_zone_ac_mangle_setup,
		      [SCG_ZONE_END]	= ipt_scg_zone_end_mangle_setup,
		      [CLOSE]		= ipt_close_mangle_setup,
	},

	[NAT]     = { [ROOT]		= ipt_root_nat_setup,
		      [TABLE]		= ipt_if_nat_setup,
		      [SCG_NAT]		= ipt_scg_nat_nat_setup,
		      [SCG_ZONE]	= ipt_scg_zone_nat_setup,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= ipt_scg_zone_ac_nat_setup,
		      [SCG_ZONE_END]	= NULL,
		      [CLOSE]		= ipt_close_nat_setup,
	},

	[FILTER]  = { [ROOT]		= ipt_root_filter_setup,
		      [TABLE]		= ipt_if_filter_setup,
		      [SCG_NAT]		= NULL,
		      [SCG_ZONE]	= ipt_scg_zone_filter_setup,
		      [SCG_ZONE_ACCNET]	= NULL,
		      [SCG_ZONE_AC]	= ipt_scg_zone_ac_filter_setup,
		      [SCG_ZONE_END]	= ipt_scg_zone_end_filter_setup,
		      [CLOSE]		= ipt_close_filter_setup,
	},
};

static void ipt_chain(FILE *ipt, enum ipt_type type)
{
	ENTER();

	fprintf(ipt, "*%s\n", ipt_names[type]);
	ipt_process(ipt, ipt_init_tab[type]);
	ipt_process(ipt, ipt_setup_tab[type]);
	fprintf(ipt, "COMMIT\n");

	EXIT();
}


static void ipt_init_dhcpfwd(const char *device, const char *ip)
{
	insmod("xt_TCPMSS");

	vasystem("iptables -A FORWARD -i %s+ -d %s -p udp --dport 67 -j ACCEPT", device, ip);
	vasystem("iptables -A FORWARD -i %s+ -p udp -s %s --sport 67 -j ACCEPT", device, ip);
	vasystem("iptables -A FORWARD -i %s+ -p udp --dport 67 -j DROP", device);

	vsystem("iptables -t mangle -A FORWARD -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu");

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
	FILE *ipt;
	int ret;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPRelay */
	if (tr069_get_bool_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							cwmp__IGD_LANDevice,
							1,
							cwmp__IGD_LANDev_i_LANHostConfigManagement,
							cwmp__IGD_LANDev_i_HostCfgMgt_DHCPRelay, 0})) {
		/** VAR: InternetGatewayDevice.LANDevice.1 */
		const char *wan = get_if_device((tr069_selector){cwmp__InternetGatewayDevice,
								 cwmp__IGD_LANDevice,
								 1, 0});
		/** VAR:InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.X_TPOSS_DHCPForwardServer */
		const char *fwdip = tr069_get_string_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
										  cwmp__IGD_LANDevice,
										  1,
										  cwmp__IGD_LANDev_i_LANHostConfigManagement,
										  cwmp__IGD_LANDev_i_HostCfgMgt_X_TPOSS_DHCPForwardServer, 0});
		debug("(): wan: %s, ip: %s", wan, fwdip);
		if (wan && fwdip)
			ipt_init_dhcpfwd(wan, fwdip);
		EXIT();
		return;
	}

#if KERNEL_VERSION > 2006000
	/* conntrack netlink */
	insmod("nfnetlink");
	insmod("nfnetlink_log");
	insmod("nfnetlink_queue");
	insmod("nf_conntrack_netlink");

	insmod("xt_state");
	insmod("xt_mac");
	insmod("xt_connmark");
	insmod("xt_MARK");
	insmod("xt_CLASSIFY");
	insmod("xt_CONNMARK");
	insmod("nf_tproxy_core");
	insmod("xt_TPROXY");
	insmod("xt_socket");
	insmod("xt_TCPMSS");
	insmod("xt_NFLOG");
	insmod("xt_NFQUEUE");
#else
	insmod("ipt_CLASSIFY");
#endif
	insmod("ipt_MASQUERADE");
	insmod("ipt_REDIRECT");
	insmod("ipt_REJECT");
	insmod("ipt_ACCOUNT");
	insmod("ipt_state");
	insmod("ipt_multiport");
	insmod("ipt_ipp2p");

	/* ipset */
	insmod("ip_set");
	insmod("ip_set_iphash");
	insmod("ip_set_iphash_nat");
	insmod("ip_set_ipporthash2");
	insmod("ip_set_ipmap");
	insmod("ip_set_iptree");
	insmod("ip_set_macipmap");
	insmod("ip_set_nethash");
	insmod("ip_set_portmap");
	insmod("ipt_set");
	insmod("ipt_SET");
	insmod("ipt_SETNAT");

	if (!ipt_target_flags)
		calc_target_flags();

	if (!ipt_match_flags)
		calc_match_flags();

	if (!ipt_chain_flags)
		calc_chain_flags();

	IF_TARGET_FLAG(TARGET_TPROXY) {
		vasystem("/usr/sbin/ip rule del fwmark 0x%x/0x%x priority 1 lookup 1", TPROXY_MARK(1), TPROXY_MASK);
		vasystem("/usr/sbin/ip rule add fwmark 0x%x/0x%x priority 1 lookup 1", TPROXY_MARK(1), TPROXY_MASK);
		vasystem("/usr/sbin/ip route add local 0.0.0.0/0 dev lo table 1");
	}

#if defined(FILEOUT)
	ipt = fopen("/tmp/iptables-restore", "w");
#else
	ipt = popen("iptables-restore", "w");
#endif

	if (!ipt) {
		debug("failed to popen iptables: %s", strerror(errno));
		EXIT();
		return;
	}

	ipt_chain(ipt, RAW);
	ipt_chain(ipt, MANGLE);
	ipt_chain(ipt, NAT);
	ipt_chain(ipt, FILTER);

#if defined(FILEOUT)
	ret = fclose(ipt);
#else
	ret = pclose(ipt);
#endif
	debug("closed pipe with status: %d", ret);

	fw_running = 1;

	EXIT();
	return;
}

void scg_acl_init()
{
	debug(": no ACLs needed");
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

#if 0 /* proxyd currently unusable */
	reload_proxy();
#endif
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

//	scg_acl_init();
}
