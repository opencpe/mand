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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>

#include <sys/tree.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#define SDEBUG
#include "debug.h"

#include "process.h"
#include "ifup.h"
#include "client.h"
#include "dhcp.h"

#define UDHCPD "/usr/sbin/udhcpd"
#define DHCPFWD "/usr/bin/dhcp-fwd"

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

static inline void
stop_dhcpfwd(const char *lan)
{
	char pidname[1024];

	snprintf(pidname, sizeof(pidname), "%s-%s", PID_DIR "/dhcpd.pid", lan);
	killpidfile(pidname);
}

static int start_dhcpfwd(const char *wan, const char *lan, struct tr069_value_table *hcm)
{
	FILE *fout;
	char fname[1024];
	char pidname[1024];
	const char *fwdip;
	const char *tmp;

	ENTER();

	snprintf(pidname, sizeof(pidname), "%s-%s", PID_DIR "/dhcpd.pid", lan);

	if (!lan || !wan) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.X_TPOSS_DHCPForwardServer */
	fwdip = tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_X_TPOSS_DHCPForwardServer);

	snprintf(fname, sizeof(fname), "/var/etc/dhcpfwd-%s.conf", lan);
	fout = fopen(fname, "w+");
	if (!fout) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_FQHostname */
	tmp = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_DeviceInfo,
				cwmp__IGD_DevInf_X_TPLINO_FQHostname, 0 });
	if (!tmp)
		tmp ="TPLINO";

	/* #       IFNAME  clients servers bcast */
	if (strcmp(wan, lan) == 0)
		fprintf(fout, "if\t%s\ttrue\ttrue\ttrue\n", lan);
	else {
		fprintf(fout, "if\t%s\ttrue\tfalse\ttrue\n", lan);
		fprintf(fout, "if\t%s\tfalse\ttrue\tfalse\n", wan);
	}
	fprintf(fout, "name\t%s\t%s#%s\tNOREMOTE\n", lan, tmp, lan);
	fprintf(fout, "server\tip\t%s\n", fwdip);
	fprintf(fout, "pidfile\t%s\n", pidname);

	fclose(fout);

	char *argv[] = {DHCPFWD, "-c", fname, NULL};
	start_daemon(argv);

	EXIT();
	return 1;
}

int dhcp_update_wan_ip(const char *wan, const tr069_selector sel)
{
	const char *lan;
	struct tr069_value_table *hcm;

	ENTER();
	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return 0;
	}

	lan = get_if_device(sel);
	if (!lan) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.{i} */
	hcm = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							    cwmp__IGD_LANDevice,
							    sel[2],
							    cwmp__IGD_LANDev_i_LANHostConfigManagement,
							    0} );

	if (!hcm) {
		EXIT();
		return 0;
	}

	stop_dhcpfwd(lan);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPServerEnable */
	if (!tr069_get_bool_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPServerEnable)) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPRelay */
	if (tr069_get_bool_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPRelay)) {
		if (!start_dhcpfwd(wan, lan, hcm)) {
			EXIT();
			return 0;
		}
	}

	EXIT();
	return 1;
}

int start_dhcpd(const char *device, const tr069_selector sel)
{
	struct tr069_value_table *hcm;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.{i} */
	hcm = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							    cwmp__IGD_LANDevice,
							    sel[2],
							    cwmp__IGD_LANDev_i_LANHostConfigManagement,
							    0} );

	if (!hcm) {
		EXIT();
		return 0;
	}

	stop_dhcpfwd(device);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPServerEnable */
	if (!tr069_get_bool_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPServerEnable)) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPRelay */
	if (tr069_get_bool_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPRelay)) {
		if (!start_dhcpfwd(device, device, hcm)) {
			EXIT();
			return 0;
		}
	}
#if !defined(WITH_DHCP_DNSMASQ)
	else {
		FILE *fout;
		char fname[1024];
		char ip[INET_ADDRSTRLEN];
		const char *addr;

		snprintf(fname, sizeof(fname), "/var/etc/udhcpd-%s.conf", device);
		fout = fopen(fname, "w+");
		if (!fout) {
			EXIT();
			return 0;
		}

		fprintf(fout, "%s\t%s\n", "interface", device);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MinAddress */
		addr = ip2str(tr069_get_ipv4_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_MinAddress), ip);
		if (addr)
			fprintf(fout, "%s\t%s\n", "start", addr);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MaxAddress */
		addr = ip2str(tr069_get_ipv4_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_MaxAddress), ip);
		if (addr)
			fprintf(fout, "%s\t%s\n", "end", addr);

		fprintf(fout, "%s\t%s-%s\n", "lease_file", "/var/run/udhcpd.leases", device);
		fprintf(fout, "%s\t%s %s\n", "notify_file", "/sbin/dhcpinfo", device);
		fprintf(fout, "%s\t%s\n", "remaining", "no");
		fprintf(fout, "%s\t%s-%s\n", "pidfile", PID_DIR "/dhcpd.pid", device);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.SubnetMask */
		addr = ip2str(tr069_get_ipv4_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_SubnetMask), ip);
		if (addr)
			fprintf(fout, "option\t%s\t%s\n", "subnet", addr);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DomainName */
		fprintf(fout, "option\t%s\t%s\n", "domain", tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DomainName));
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPLeaseTime */
		fprintf(fout, "option\t%s\t%d\n", "lease", tr069_get_int_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPLeaseTime));
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DNSServers */
		fprintf(fout, "option\t%s\t%s\n", "dns", tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DNSServers));
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPRouters */
		fprintf(fout, "option\t%s\t%s\n", "router", tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_IPRouters));

		fclose(fout);

		vasystem(UDHCPD " %s", fname);
	}
#endif

	EXIT();
	return 0;
}

void stop_dhcpd(const char *device)
{
#if !defined(WITH_DHCP_DNSMASQ)
	char fname[1024];

	snprintf(fname, sizeof(fname), "%s-%s", PID_DIR "/udhcpd.pid", device);
	killpidfile(fname);
#endif
}

/*** from udhcpd leases.h ***/

struct dhcpOfferedAddr {
	uint8_t chaddr[16];
	uint32_t yiaddr;	/* network order */
	uint32_t giaddr;	/* network order */
	uint32_t expires;	/* host order */
	uint8_t  agent_info_len;
};

static void update_dhcp_entry(struct tr069_instance_node *node,
			      const struct dhcpOfferedAddr *lease, uint8_t *agent_info)
{
	struct tr069_value_table *t = DM_TABLE(node->table);
	char mac[18];

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
	tr069_set_ipv4_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, (struct in_addr){ .s_addr = lease->yiaddr });
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
	tr069_set_enum_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource, 0);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.LeaseTimeRemaining */
	tr069_set_int_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining, ntohl(lease->expires));

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 lease->chaddr[0], lease->chaddr[1], lease->chaddr[2],
		 lease->chaddr[3], lease->chaddr[4], lease->chaddr[5]);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.MACAddress */
	tr069_set_string_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_MACAddress, mac);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.HostName */
	tr069_set_string_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_HostName, NULL);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.InterfaceType */
	tr069_set_enum_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_InterfaceType, 0);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Active */
	tr069_set_bool_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_Active, 1);

	for (int i = 0; i < lease->agent_info_len; ) {
		char tmp;

		tmp = agent_info[i + 2 + agent_info[i + 1]];
		agent_info[i + 2 + agent_info[i + 1]] = '\0';

		switch(agent_info[i]) {
		case 1:
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentCircuitId */
			tr069_set_binary_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentCircuitId,
						    agent_info[i + 1], &agent_info[i + 2]);
			break;
		case 2:
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
			tr069_set_binary_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentRemoteId,
						    agent_info[i + 1], &agent_info[i + 2]);
			break;
		default:
			break;
		}
		i += 2 + agent_info[i + 1];
		agent_info[i] = tmp;
	}
	update_instance_node_index(node);
}

struct dhcp_entry {
	RB_ENTRY (dhcp_entry) node;

	struct tr069_instance_node *entry;
	uint32_t yiaddr;
	int updated;
};

RB_HEAD(dhcp_tree, dhcp_entry);

static int
dhcp_compare(struct dhcp_entry *a, struct dhcp_entry *b)
{
	return (uint32_t)a->yiaddr - (uint32_t)b->yiaddr;
}

RB_PROTOTYPE(dhcp_tree, dhcp_entry, node, dhcp_compare);
RB_GENERATE(dhcp_tree, dhcp_entry, node, dhcp_compare);

static void
free_dhcp_subtree(struct dhcp_entry *node)
{
	if (!node)
		return;

	free_dhcp_subtree(RB_LEFT(node, node));
	free_dhcp_subtree(RB_RIGHT(node, node));
	free(node);
}

static void
free_dhcp_tree(struct dhcp_tree *head)
{
	free_dhcp_subtree(RB_ROOT(head));
}

static void hotspot_update_dhcp_lease(tr069_selector sb, struct dhcpOfferedAddr *lease, uint8_t *agent_info)
{
	char mac[18];
	binary_t *circuit = NULL;
	binary_t *remote = NULL;

	ENTER();

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 lease->chaddr[0], lease->chaddr[1], lease->chaddr[2],
		 lease->chaddr[3], lease->chaddr[4], lease->chaddr[5]);

	for (int i = 0; i < lease->agent_info_len; ) {
		switch(agent_info[i]) {
		case 1:
			circuit = malloc(sizeof(binary_t) + agent_info[i + 1]);
			if (circuit) {
				circuit->len = agent_info[i + 1];
				memcpy(circuit->data, (char *)&agent_info[i + 2], agent_info[i + 1]);
			}
			debug("(): circuit_id: %p", circuit);
			break;
		case 2:
			remote = malloc(sizeof(binary_t) + agent_info[i + 1]);
			if (remote) {
				remote->len = agent_info[i + 1];
				memcpy(remote->data, (char *)&agent_info[i + 2], agent_info[i + 1]);
			}
			debug("(): remote_id: %p", remote);
			break;
		default:
			break;
		}
		i += 2 + agent_info[i + 1];
	}

	hs_update_client_by_device(sb, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource_DHCP,
				   (struct in_addr){ .s_addr = lease->yiaddr }, mac,
				   NULL, NULL, NULL, circuit, remote, (tr069_selector){0}, time2ticks(ntohl(lease->expires)));
	free(circuit);
	free(remote);
	EXIT();
}

static pthread_mutex_t dhcpd_mutex = PTHREAD_MUTEX_INITIALIZER;

static int reread_dhcpd_leases(const char *device, const tr069_selector sel)
{
	int fd;
	char fname[1024];
	uint8_t buf[256];
	struct dhcpOfferedAddr lease;
	struct tr069_value_table *landev;
	struct tr069_value_table *hostst;
	struct tr069_instance *hostt;
	struct dhcp_tree old_entrys;
	struct dhcp_entry *dnode;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return -1;
	}

	RB_INIT(&old_entrys);

	pthread_mutex_lock(&dhcpd_mutex);

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	landev = tr069_get_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							      cwmp__IGD_LANDevice,
							      sel[2], 0});
	if (!landev) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts */
	hostst = tr069_get_table_by_id(landev, cwmp__IGD_LANDev_i_Hosts);
	if (!hostst) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host */
		tr069_add_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							     cwmp__IGD_LANDevice,
							     sel[2],
							     cwmp__IGD_LANDev_i_Hosts,
							     cwmp__IGD_LANDev_i_Hosts_Host, 0});
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts */
		hostst = tr069_get_table_by_id(landev, cwmp__IGD_LANDev_i_Hosts);
	}
	if (!hostst) {
		pthread_mutex_unlock(&dhcpd_mutex);
		EXIT();
		return -1;
	}


	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host */
	hostt = tr069_get_instance_ref_by_id(hostst, cwmp__IGD_LANDev_i_Hosts_Host);
	if (hostt) {
		struct tr069_instance_node *node;

		/*
		 * build a lookup and marker table from the old
		 * entries
		 */

		for (node = tr069_instance_first(hostt);
		     node != NULL;
		     node = tr069_instance_next(hostt, node)) {
			struct dhcp_entry *e;

			e = malloc(sizeof(struct dhcp_entry));
			if (!e)
				break;

			e->entry = node;
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
			e->yiaddr = tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress).s_addr;
			RB_INSERT(dhcp_tree, &old_entrys, e);
		}
	}

	snprintf(fname, sizeof(fname), "%s-%s", "/var/run/udhcpd.leases", device);
	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		free_dhcp_tree(&old_entrys);
		pthread_mutex_unlock(&dhcpd_mutex);
		EXIT();
		return -1;
	}

	while (read(fd, &lease, sizeof(struct dhcpOfferedAddr)) == sizeof(struct dhcpOfferedAddr)) {
		struct tr069_instance_node *host = NULL;
		struct dhcp_entry *e;

		debug("(): lease for mac: %02x:%02x:%02x:%02x:%02x:%02x",
		      lease.chaddr[0], lease.chaddr[1], lease.chaddr[2],
		      lease.chaddr[3], lease.chaddr[4], lease.chaddr[5]);

		if (lease.agent_info_len)
			read(fd, buf, lease.agent_info_len);

		e = RB_FIND(dhcp_tree, &old_entrys, &(struct dhcp_entry){ .yiaddr = lease.yiaddr });
		if (e) {
			e->updated = 1;
			host = e->entry;
			debug("(): got old entry: %p", host);
		}
		if (!host) {
			tr069_id id = TR069_ID_AUTO_OBJECT;

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i} */
			if ((host = tr069_add_instance_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
										    cwmp__IGD_LANDevice,
										    sel[2],
										    cwmp__IGD_LANDev_i_Hosts,
										    cwmp__IGD_LANDev_i_Hosts_Host, 0}, &id)) == NULL)
				continue;
		}
		hotspot_update_dhcp_lease(landev->id, &lease, buf);
		update_dhcp_entry(host, &lease, buf);
	}
	close(fd);

	RB_FOREACH(dnode, dhcp_tree, &old_entrys) {
		if (!dnode->updated) {
			debug("(): removing entry idx: %p, id: %d", dnode->entry, dnode->entry->instance);
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i} */
			tr069_del_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
						cwmp__IGD_LANDevice,
						sel[2],
						cwmp__IGD_LANDev_i_Hosts,
						cwmp__IGD_LANDev_i_Hosts_Host,
						dnode->entry->instance, 0});
		}
	}

	free_dhcp_tree(&old_entrys);
	pthread_mutex_unlock(&dhcpd_mutex);
	EXIT();
	return 0;
}

static void *dhcpinfo_thread(void *arg)
{
	const char *argv[10];
	int argc = 0;
	char *cmd = (char *)arg;
	struct tr069_instance *base;

	chomp(cmd);
	syslog(LOG_KERN|LOG_NOTICE|LOG_FACMASK|LOG_DAEMON, "%s", cmd);

	while(argc < 10 && cmd && *cmd) {
		argv[argc++] = cmd;

		if ((cmd = strchr(cmd, ' ')) != NULL)
			*cmd++ = '\0';
	}

	for (int i = 0; i < argc; i++)
		debug("(): argv[%d]: %s", i, argv[i]);

	if (argc < 1)
		goto out;

	base = get_if_layout(argv[0]);
	call_if_func(argv[0], base, IF_NONE, reread_dhcpd_leases);

 out:
	free(cmd);

	return NULL;
}

void dhcpinfo(const char *cmd)
{
	pthread_t tid;
	char *s;

	s = strdup(cmd);
	pthread_create(&tid, NULL, dhcpinfo_thread, (void *)s);
	pthread_detach(tid);
}

void dm_relay_action(const tr069_selector sel __attribute__((unused)),
			     enum dm_action_type type __attribute__((unused)))
{
	const tr069_selector *lan;
	const char *ppp, *cld = "Could not ";

	ENTER();

	if(!(ppp = get_if_device((tr069_selector){cwmp__InternetGatewayDevice,
							cwmp__IGD_X_TPLINO_NET_NetworkGateway, 0}))) {
		debug("(): %smap ppp device selector.", cld);
		goto err;
	}

	if(!(lan = tr069_get_selector_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							cwmp__IGD_X_TPLINO_NET_NetworkGateway,
							cwmp__IGD_LNG_LANDevice, 0}))) {
		debug("(): %sretrieve LNG landevice.", cld);
		goto err;
	}

	if(!dhcp_update_wan_ip(ppp, *lan))
		debug("(): Dynamic dhcp setup failed!");

err:
	EXIT();
	return;
}
