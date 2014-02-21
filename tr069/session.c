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
#include <pthread.h>

#ifdef HAVE_IPT_ACCOUNT_CL_H
#include <ipt_ACCOUNT_cl.h>
#endif
#ifdef HAVE_LIBXT_ACCOUNT_CL_H
#include <linux/types.h>
#include <libxt_ACCOUNT_cl.h>
#endif

#include <ev.h>

#include "dm_assert.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_action.h"

#include "ifup.h"
#include "l3forward.h"
#include "connmark.h"
#include "session.h"
#include "process.h"
#include "firewall.h"
#include "client.h"

#define SDEBUG
#include "debug.h"

#define TC_ENABLED 1
#define TC "/usr/sbin/tc"

#define IPTABLES "/usr/sbin/iptables"

#define iptables_do_command(fmt, ...)    vasystem(IPTABLES " " fmt, __VA_ARGS__)
#define tc_do_command(fmt, ...)          vasystem(TC " " fmt, __VA_ARGS__)

/* storage size of the unique Id is SCG_BITS_ZONE+SCG_BITS_ACCESSCLASS bits */
#define UNIQUE_AC_ID(ZONE, AC) \
	((((ZONE) & SCG_MASK_ZONE) << SCG_BITS_ACCESSCLASS) | ((AC) & SCG_MASK_ACCESSCLASS))

/** Remove the firewall rules
 * This is used when we do a clean shutdown of the GateWay and when it starts to make
 * sure there are no rules left over
 */
int iptables_fw_destroy(void)
{
    int id;

    id = 1;

    iptables_do_command("-t mangle -F LD_%d_GW_%s", id, TABLE_GW_OUTGOING);
    iptables_do_command("-t mangle -F LD_%d_GW_%s", id, TABLE_GW_INCOMING);
    return 0;
}

#define min_not_zero(x, y) (y != 0 && y < x ? y : x)

#if 0

/*
 * QoS Stuff
 */

/*
 * create class and put client into it
 */
	int up, down;
	struct tr069_value_table *hst;

	const char *wan = get_wan_device(1);
	const char *hs = get_if_device(iface);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig */
	hst = tr069_get_table_by_id(DM_TABLE(ift->table), cwmp__IGD_LANDev_i_HotSpotConfig);
	if (!hst) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthUp */
	up = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthUp);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthDown */
	down = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthDown);

	if (up && down) {
		int cls;
		unsigned int min_up, max_up, min_down, max_down;

		cls = (ntohl(in.s_addr) & 0xFF) + 256;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.Clients.{i}.BandwidthMinUp */
		if (!(min_up = tr069_get_uint_by_id(clnt, cwmp__IGD_LANDev_i_HSCfg_Clnts_j_BandwidthMinUp)))
			/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.DefaultBandwidthMinUp */
			min_up = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_DefaultBandwidthMinUp);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthMinUp */
		min_up = min_not_zero(min_up, tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthMinUp));

		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.Clients.{i}.BandwidthMaxUp */
		if (!(max_up = tr069_get_uint_by_id(clnt, cwmp__IGD_LANDev_i_HSCfg_Clnts_j_BandwidthMaxUp)))
			/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.DefaultBandwidthMaxUp */
			max_up = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_DefaultBandwidthMaxUp);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthMaxUp */
		max_up = min_not_zero(max_up, tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthMaxUp));

		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.Clients.{i}.BandwidthMinDown */
		if (!(min_down = tr069_get_uint_by_id(clnt, cwmp__IGD_LANDev_i_HSCfg_Clnts_j_BandwidthMinDown)))
			/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.DefaultBandwidthMinDown */
			min_down = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_DefaultBandwidthMinDown);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthMinDown */
		min_down = min_not_zero(min_down, tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthMinDown));

		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.Clients.{i}.BandwidthMaxDown */
		if (!(max_down = tr069_get_uint_by_id(clnt, cwmp__IGD_LANDev_i_HSCfg_Clnts_j_BandwidthMaxDown)))
			/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.DefaultBandwidthMaxDown */
			max_down = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_DefaultBandwidthMaxDown);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthMaxDown */
		max_down = min_not_zero(max_down, tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthMaxDown));

		iptables_do_command("-t mangle -A LD_%d_GW_%s -s %s -j CLASSIFY --set-class 1:%d",
				    id, TABLE_GW_CLASSIFY, ip, cls);
		iptables_do_command("-t mangle -A LD_%d_GW_%s -d %s -j CLASSIFY --set-class 1:%d",
				    id, TABLE_GW_CLASSIFY, ip, cls);
		tc_do_command("class add dev %s parent 1:1 classid 1:%d htb rate %dbps ceil %dbps quantum 1500", wan, cls, min_up, max_up);
		tc_do_command("class add dev %s parent 1:1 classid 1:%d htb rate %dbps ceil %dbps quantum 1500", hs, cls, min_down, max_down);
	}



/*
 * remove client from class and destroy it
 */

	int up, down;
	struct tr069_value_table *hst;

	const char *wan = get_wan_device(1);
	const char *hs = get_if_device(iface);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig */
	hst = tr069_get_table_by_id(DM_TABLE(ift->table), cwmp__IGD_LANDev_i_HotSpotConfig);
	if (!hst) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthUp */
	up = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthUp);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthDown */
	down = tr069_get_uint_by_id(hst, cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthDown);

	if (up && down) {
		int cls;

		cls = (ntohl(in.s_addr) & 0xFF) + 256;

		iptables_do_command("-t mangle -D LD_%d_GW_%s -s %s -j CLASSIFY --set-class 1:%d",
				    id, TABLE_GW_CLASSIFY, ip, cls);
		iptables_do_command("-t mangle -D LD_%d_GW_%s -d %s -j CLASSIFY --set-class 1:%d",
				    id, TABLE_GW_CLASSIFY, ip, cls);
		tc_do_command("class del dev %s parent 1:1 classid 1:%d", wan, cls);
		tc_do_command("class del dev %s parent 1:1 classid 1:%d", hs, cls);
	}


#endif


int fw_allow(tr069_id zone, struct tr069_value_table *clnt, struct tr069_value_table *act)
{
	int rc;
	tr069_id ac;
	struct in_addr in;
	char ip[INET_ADDRSTRLEN];

	ENTER();

	if (!act) {
		EXIT();
		return 1;
	}
	ac = act->id[6];

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	in = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
	inet_ntop(AF_INET, &in, ip, sizeof(ip));

	rc = vasystem("/usr/sbin/ipset -A SCG_%d_CLASSIFY_%d %s", zone, ac, ip);

	if (rc == 0) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Stats */
		struct tr069_value_table *stats = tr069_get_table_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats);
		if (!stats) {
			tr069_add_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							cwmp__IGD_X_TPLINO_NET_SessionControl,
							cwmp__IGD_SCG_Zone,
							act->id[3],
							cwmp__IGD_SCG_Zone_i_AccessClasses,
							cwmp__IGD_SCG_Zone_i_ACs_AccessClass,
							act->id[6],
							cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats, 0});
			stats = tr069_get_table_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats);
		}
		if (stats)
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Stats.Clients */
			tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats_Clients);
	}

	EXIT();
	return rc;
}

int fw_deny(tr069_id zone, struct tr069_value_table *clnt, struct tr069_value_table *act)
{
	int rc;
	tr069_id ac;
	struct in_addr in;
	char ip[INET_ADDRSTRLEN];

	ENTER();

	if (!act) {
		EXIT();
		return 1;
	}
	ac = act->id[6];

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	in = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
	inet_ntop(AF_INET, &in, ip, sizeof(ip));

	rc = vasystem("/usr/sbin/ipset -D SCG_%d_CLASSIFY_%d %s", zone, ac, ip);

	if (rc == 0) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Stats */
		struct tr069_value_table *stats = tr069_get_table_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats);

		if (stats)
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Stats.Clients */
			tr069_decr_uint_by_id(stats, cwmp__IGD_SCG_Zone_i_ACs_AC_j_Stats_Clients);
	}

	EXIT();
	return rc;
}

int fw_natp_create(struct tr069_value_table *natp, struct tr069_value_table *clnt)
{
	int rc = 0;
	struct in_addr ip;
	struct in_addr nat;
	unsigned int start_port;
	unsigned int end_port;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	ip = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	nat = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
	start_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
	end_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd);

	if (ip.s_addr != INADDR_ANY && ip.s_addr != INADDR_NONE &&
	    nat.s_addr != INADDR_ANY && nat.s_addr != INADDR_NONE) {
		char ports[20];
		char ips[INET_ADDRSTRLEN];
		char nats[INET_ADDRSTRLEN];

		ports[0] = '\0';
		if (start_port != 0 || end_port != 0)
			snprintf(ports, sizeof(ports), ":%d-%d", start_port, end_port);

		inet_ntop(AF_INET, &ip, ips, sizeof(ips));
		inet_ntop(AF_INET, &nat, nats, sizeof(nats));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.Translation */
		switch (tr069_get_enum_by_id(natp, cwmp__IGD_SCG_NP_i_Translation)) {
		case cwmp___IGD_SCG_NP_i_Translation_SymetricAddressKeyed:
			rc = vasystem("/usr/sbin/ipset -A DNATP_%d %s,%s", natp->id[3], nats, ips);

		case cwmp___IGD_SCG_NP_i_Translation_AddressKeyed:
		case cwmp___IGD_SCG_NP_i_Translation_PortKeyed:
			rc = vasystem("/usr/sbin/ipset -A SNATP_%d %s,%s%s", natp->id[3], ips, nats, ports);
			break;
		}
	}

	EXIT();
	return rc;
}

int fw_natp_remove(struct tr069_value_table *natp, struct tr069_value_table *clnt)
{
	int rc = 0;
	struct in_addr ip;
	struct in_addr nat;
	unsigned int start_port;
	unsigned int end_port;
	char ips[INET_ADDRSTRLEN];

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	ip = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	nat = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
	start_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
	end_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd);

	if (ip.s_addr != INADDR_ANY && ip.s_addr != INADDR_NONE &&
	    nat.s_addr != INADDR_ANY && nat.s_addr != INADDR_NONE) {
		char ports[20];
		char nats[INET_ADDRSTRLEN];

		ports[0] = '\0';
		if (start_port != 0 || end_port != 0)
			snprintf(ports, sizeof(ports), ":%d-%d", start_port, end_port);

		inet_ntop(AF_INET, &ip, ips, sizeof(ips));
		inet_ntop(AF_INET, &nat, nats, sizeof(nats));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.Translation */
		switch (tr069_get_enum_by_id(natp, cwmp__IGD_SCG_NP_i_Translation)) {
		case cwmp___IGD_SCG_NP_i_Translation_SymetricAddressKeyed:
			rc = vasystem("/usr/sbin/ipset -D DNATP_%d %s,%s", natp->id[3], nats, ips);

		case cwmp___IGD_SCG_NP_i_Translation_AddressKeyed:
		case cwmp___IGD_SCG_NP_i_Translation_PortKeyed:
			rc = vasystem("/usr/sbin/ipset -D SNATP_%d %s,%s%s", natp->id[3], ips, nats, ports);
			break;
		}
	}

#if defined(WITH_CONNTRACK_TOOLS)
	if (ip.s_addr != INADDR_ANY && ip.s_addr != INADDR_NONE) {
		rc = vasystem("/usr/sbin/conntrack -D --orig-src %s", ips);
		rc = vasystem("/usr/sbin/conntrack -D --reply-src %s", ips);
		rc = vasystem("/usr/sbin/conntrack -D --reply-dst %s", ips);
	}
#endif

	EXIT();
	return rc;
}

/*
 * remove all pending conntrack entries for this client
 */
int fw_clnt_cleanup(struct tr069_value_table *clnt)
{
	int rc = 0;
	struct in_addr ip;

	ENTER();

#if defined(WITH_CONNTRACK_TOOLS)
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	ip = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);

	if (ip.s_addr != INADDR_ANY && ip.s_addr != INADDR_NONE) {
		char ips[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &ip, ips, sizeof(ips));

		rc = vasystem("/usr/sbin/conntrack -D --orig-src %s", ips);
		rc = vasystem("/usr/sbin/conntrack -D --reply-src %s", ips);
	}
#endif

	EXIT();
	return rc;
}

#if defined(HAVE_IPT_ACCOUNT_CL_H) || defined(HAVE_LIBXT_ACCOUNT_CL_H)

static struct ipt_ACCOUNT_context *ipt_ctx = NULL;

static struct ipt_ACCOUNT_context *get_ipt_ctx(void)
{
	if (!ipt_ctx) {
		ipt_ctx = malloc(sizeof(struct ipt_ACCOUNT_context));
		if (!ipt_ctx)
			return NULL;

		if (ipt_ACCOUNT_init(ipt_ctx) != 0) {
			debug("init failed: %s\n", ipt_ctx->error_str);
			free(ipt_ctx);
			ipt_ctx = NULL;
		}
	}
	return ipt_ctx;
}

static void close_ipt_ctx(void)
{
	ipt_ACCOUNT_deinit(ipt_ctx);
	free(ipt_ctx);
	ipt_ctx = NULL;
}

#if defined(SDEBUG)
static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}
#endif

/** Update the counters of all the clients in the client list */
void iptables_fw_counters_update(struct tr069_instance_node *zone)
{
	struct ipt_ACCOUNT_context *ctx;
	struct tr069_value_table *accounting;
	struct tr069_instance *subnets;
	struct tr069_instance_node *net;
	struct tr069_value_table *clnts;
	struct tr069_instance *clnt;
	ticks_t rt_now;

	ENTER();

	int id = zone->instance;

	ctx = get_ipt_ctx();
	if (!ctx) {
		EXIT();
		return;
	}

	accounting = tr069_get_table_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_Accounting);
	if (!accounting) {
		EXIT();
		return;
	}

	subnets = tr069_get_instance_ref_by_id(accounting, cwmp__IGD_SCG_Zone_i_Acc_SubNets);
	if (!subnets) {
		EXIT();
		return;
	}

	clnts = tr069_get_table_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_Clients);
	if (!clnts) {
		EXIT();
		return;
	}

	clnt = tr069_get_instance_ref_by_id(clnts, cwmp__IGD_SCG_Zone_i_Clnts_Client);
	if (!clnt) {
		EXIT();
		return;
	}

	rt_now = ticks();

	for (net = tr069_instance_first(subnets);
	     net != NULL;
	     net = tr069_instance_next(subnets, net))
	{
		char name[32];
		struct ipt_acc_handle_ip *entry;

		if (!tr069_get_bool_by_id(DM_TABLE(net->table), cwmp__IGD_SCG_Zone_i_Acc_SN_j_Enabled))
			continue;

		snprintf(name, sizeof(name), "account_%d_%d", id, net->instance);

		/* Get entries from table test */
		if (ipt_ACCOUNT_read_entries(ctx, name, 0)) {
			debug("Read failed: %s\n", ctx->error_str);
			close_ipt_ctx();
			EXIT();
			return;
		}

		// Output and free entries
		while ((entry = ipt_ACCOUNT_get_next_entry(ctx)) != NULL) {
			struct tr069_instance_node *n;
			struct tr069_value_table *c;
			uint64_t inOctets;
			uint64_t outOctets;
			uint64_t maxInOctets;
			uint64_t maxOutOctets;
			uint64_t maxTotalOctets;

#if defined(SDEBUG)
			char b1[128];
			char buf[INET_ADDRSTRLEN];
			const char *ip = NULL;

			ip = ip2str(*(struct in_addr *)&entry->ip, buf);
#endif

			debug("(): searching for: %s\n", ip ? ip : "NULL");

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
			n = find_instance(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress,
					  T_IPADDR4, &init_DM_IP4(*(struct in_addr *)&entry->ip, 0));
			if (!n) {
				debug("(): could no find node for: %s\n", ip ? ip : "NULL");
				continue;
			}

			c = DM_TABLE(n->table);

			debug("(): got client sel: %s\n", sel2str(b1, c->id));

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutOctets */
			outOctets = tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets) + entry->dst_bytes;
			tr069_set_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets, outOctets);

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutPackets */
			tr069_set_uint_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutPackets,
					     tr069_get_uint_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutPackets) + entry->dst_packets);

			debug("%s - Updated OUT counter to %" PRIu64 " bytes, %" PRIu32 " pkts",
			      ip,
			      tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets),
			      tr069_get_uint_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutPackets));

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InOctets */
			inOctets = tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets) + entry->src_bytes;
			tr069_set_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets, inOctets);

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InPackets */
			tr069_set_uint_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InPackets,
					     tr069_get_uint_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InPackets) + entry->src_packets);

			debug("%s - Updated IN counter to %" PRIu64 " bytes, %" PRIu32 " pkts",
			      ip,
			      tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets),
			      tr069_get_uint_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InPackets));

			tr069_set_ticks_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastCounterUpdate, rt_now);

			maxInOctets = tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxInputOctets);
			maxOutOctets = tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxOutputOctets);
			maxTotalOctets = tr069_get_uint64_by_id(c, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxTotalOctets);
			if ((maxInOctets    != 0 && inOctets  >= maxInOctets) ||
			    (maxOutOctets   != 0 && outOctets >= maxOutOctets) ||
			    (maxTotalOctets != 0 && inOctets + outOctets >= maxTotalOctets))
				scg_client_volume_exhausted(DM_TABLE(zone->table), c, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Session_Timeout);
		}
	}

	EXIT();
}

#else

void iptables_fw_counters_update(struct tr069_instance_node *zone __attribute__((unused)))
{
	EXIT_MSG(": unimplemented");
}

#endif

struct zone_info {
	ev_timer timer;
	struct tr069_instance_node *zone;
};

static void zonetimer_cb(EV_P_ ev_timer *w, int revents __attribute__ ((unused)))
{
	struct zone_info *zi = (struct zone_info *)w;

	dm_assert(zi);
	dm_assert(zi->zone);

	iptables_fw_counters_update(zi->zone);

	ev_timer_again (EV_A_ w);
}

static void stop_zone_timer(struct zone_info *zi)
{
	if (!zi)
		return;

	if (ev_is_active(&zi->timer))
		ev_timer_stop(EV_DEFAULT_UC_ &zi->timer);
}

static int start_zone_timer(struct tr069_instance_node *zone)
{
	struct zone_info *zi;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.X_DM_ZoneInfo */
	zi = tr069_get_ptr_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_X_DM_ZoneInfo);
	if (!zi) {
		zi = malloc(sizeof(struct zone_info));
		if (!zi) {
			EXIT();
			return 0;
		}

		memset(zi, 0, sizeof(struct zone_info));
		zi->zone = zone;
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.X_DM_ZoneInfo */
		tr069_set_ptr_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_X_DM_ZoneInfo, zi);
	} else
		stop_zone_timer(zi);

        ev_timer_init(&zi->timer, zonetimer_cb, 0., 1.);
        ev_timer_again(EV_DEFAULT_UC_ &zi->timer);

	EXIT();
	return 1;
}

void del_IGD_SCG_Zone(const struct tr069_table *kw __attribute__ ((unused)),
		      tr069_id id __attribute__ ((unused)),
		      struct tr069_instance *inst __attribute__ ((unused)),
		      struct tr069_instance_node *node)
{
	struct tr069_value_table *zone = DM_TABLE(node->table);
	struct tr069_value_table *acs;
	struct tr069_instance *ac;
	struct zone_info *zi;
#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.X_DM_ZoneInfo */
	zi = tr069_get_ptr_by_id(zone, cwmp__IGD_SCG_Zone_i_X_DM_ZoneInfo);
	if (zi) {
		stop_zone_timer(zi);
		free(zi);
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses */
	acs = tr069_get_table_by_id(zone, cwmp__IGD_SCG_Zone_i_AccessClasses);
	if (!acs) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	ac = tr069_get_instance_ref_by_id(acs, cwmp__IGD_SCG_Zone_i_ACs_AccessClass);
	if (!ac) {
		EXIT();
		return;
	}

	for (struct tr069_instance_node *acnode = tr069_instance_first(ac);
	     acnode != NULL;
	     acnode = tr069_instance_next(ac, acnode))
	{
		debug(": AccessClass: %s\n", sel2str(b1, DM_TABLE(acnode->table)->id));

		unregister_l3_policy(-1 /* placeholder */, UNIQUE_AC_ID(node->idm, acnode->idm),
				     scg_mark(node->idm, acnode->idm, 0, 0),
				     SCG_POS_MASK_ZONE | SCG_POS_MASK_ACCESSCLASS);
	}

	EXIT();
}

int start_scg_zones(void)
{
	struct tr069_instance *zones;
	struct tr069_instance_node *zone;

	zones = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0 });
	if (zones)
		for (zone = tr069_instance_first(zones);
		     zone != NULL;
		     zone = tr069_instance_next(zones, zone))
			start_zone_timer(zone);

	return 0;
}

int scg_zones_init(void)
{
	struct tr069_instance *zones;
	struct tr069_instance_node *zone;
#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER();

	zones = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0 });
	if (zones)
		for (zone = tr069_instance_first(zones);
		     zone != NULL;
		     zone = tr069_instance_next(zones, zone))
		{
			struct tr069_value_table *acs;
			struct tr069_instance *ac;
			struct tr069_instance_node *node;

			debug(": Zone: %s\n", sel2str(b1, DM_TABLE(zone->table)->id));

			if (!tr069_get_bool_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_Enabled))
				continue;

			acs = tr069_get_table_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_AccessClasses);
			if (!acs)
				continue;

			if ((ac = tr069_get_instance_ref_by_id(acs, cwmp__IGD_SCG_Zone_i_ACs_AccessClass)))
				for (node = tr069_instance_first(ac);
				     node != NULL;
				     node = tr069_instance_next(ac, node))
				{
					int l3policy;

					debug(": AccessClass: %s\n", sel2str(b1, DM_TABLE(node->table)->id));

					if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_Enabled))
						continue;

					l3policy = tr069_get_int_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_ForwardingPolicy);
					debug(": ForwardingPolicy: %d", l3policy);
					if (l3policy > 0)
						register_l3_policy(l3policy, UNIQUE_AC_ID(zone->idm, node->idm),
								   scg_mark(zone->idm, node->idm, 0, 0),
								   SCG_POS_MASK_ZONE | SCG_POS_MASK_ACCESSCLASS);
				}
		}

	EXIT();
	return 0;
}

void dm_zone_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": execute for zone: %s, type: %d", sel2str(b1, sel), type);

	/* TODO: kill the running zone and restart it.... */
}

void del_IGD_SCG_Zone_i_ACs_AccessClass(const struct tr069_table *kw __attribute__((unused)),
					tr069_id id __attribute__((unused)),
					struct tr069_instance *inst __attribute__((unused)),
					struct tr069_instance_node *node)
{
	struct tr069_instance_node *zone;
	tr069_selector sel;
#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	tr069_selcpy(sel, DM_TABLE(node->table)->id);
	sel[4] = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	if (!(zone = tr069_get_instance_node_by_selector(sel))) {
		EXIT_MSG(": Zone already deleted: %s", sel2str(b1, sel));
		return;
	}

	unregister_l3_policy(-1 /* placeholder */, UNIQUE_AC_ID(zone->idm, node->idm),
			     scg_mark(zone->idm, node->idm, 0, 0),
			     SCG_POS_MASK_ZONE | SCG_POS_MASK_ACCESSCLASS);

	EXIT();
}

void dm_l3policy_action(const tr069_selector sel, enum dm_action_type type)
{
	struct tr069_instance_node *zone;
	int zenabled;

	struct tr069_value_table *acs;
	struct tr069_instance *ac;

#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER();

	if (type != DM_CHANGE) {
		EXIT_MSG(": type %d already handled", type);
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	if (!(zone = tr069_get_instance_node_by_selector(sel))) {
		EXIT_MSG(": Zone already deleted: %s", sel2str(b1, sel));
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
	zenabled = tr069_get_bool_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_Enabled);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses */
	acs = tr069_get_table_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_AccessClasses);
	if (!acs) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	ac = tr069_get_instance_ref_by_id(acs, cwmp__IGD_SCG_Zone_i_ACs_AccessClass);
	if (!ac) {
		EXIT();
		return;
	}

	for (struct tr069_instance_node *acnode = tr069_instance_first(ac);
	     acnode != NULL;
	     acnode = tr069_instance_next(ac, acnode))
	{
		int l3policy;

		debug(": AccessClass: %s\n", sel2str(b1, DM_TABLE(acnode->table)->id));

		unregister_l3_policy(-1 /* placeholder */, UNIQUE_AC_ID(zone->idm, acnode->idm),
				     scg_mark(zone->idm, acnode->idm, 0, 0),
				     SCG_POS_MASK_ZONE | SCG_POS_MASK_ACCESSCLASS);

		if (!zenabled ||
		    /** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.Enabled */
		    !tr069_get_bool_by_id(DM_TABLE(acnode->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_Enabled))
			continue;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.ForwardingPolicy */
		l3policy = tr069_get_int_by_id(DM_TABLE(acnode->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_ForwardingPolicy);
		debug(": ForwardingPolicy: %d", l3policy);
		if (l3policy < 0)
			continue;

		register_l3_policy(l3policy, UNIQUE_AC_ID(zone->idm, acnode->idm),
				   scg_mark(zone->idm, acnode->idm, 0, 0),
				   SCG_POS_MASK_ZONE | SCG_POS_MASK_ACCESSCLASS);
	}

	EXIT();
}

