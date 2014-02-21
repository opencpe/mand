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

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#include <talloc/talloc.h>
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/diammsg.h"
#include "libdmconfig/codes.h"

#include "tr069.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_cache.h"
#include "tr069_cfgsessions.h"
#include "tr069_dmconfig.h"
#include "ifup.h"
#include "dnsmasq.h"
#include "client.h"
#include "dhcp.h"

#define SDEBUG
#include "debug.h"

#if defined(WITH_DHCP_DNSMASQ)

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}

static void dhcp_static(FILE *fout, int land, struct tr069_instance *staticIP)
{
	struct tr069_instance_node *node;

	ENTER();

	for (node = tr069_instance_first(staticIP);
	     node != NULL;
	     node = tr069_instance_next(staticIP, node)) {
		char ipbuf[INET_ADDRSTRLEN];
		const char *ip = NULL;
		const char *mac;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Enable */
		if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPStatic_k_Enable))
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Chaddr */
		mac = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPStatic_k_Chaddr);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Yiaddr */
		ip = ip2str(tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPStatic_k_Yiaddr), ipbuf);

		if (ip && mac)
			fprintf(fout, "dhcp-host=net:ld%d,%s,%s\n", land, mac, ip);
	}
	EXIT();
}

static void dhcp_options(FILE *fout, int land, struct tr069_instance *options)
{
	struct tr069_instance_node *node;

	ENTER();

	for (node = tr069_instance_first(options);
	     node != NULL;
	     node = tr069_instance_next(options, node)) {
		unsigned int tag;
		const binary_t *value;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption.{i}.Enable */
		if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPOption_k_Enable))
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption.{i}.Tag */
		tag = tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPOption_k_Tag);

		/*FIXME: Value is binary, not string */
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption.{i}.Value */
		value = tr069_get_binary_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPOption_k_Value);

		if (value->len > 0) {
			unsigned int i;

			fprintf(fout, "dhcp-option=net:ld%d,%d,", land, tag);
			for (i = 0; i < value->len - 1; i++)
				fprintf(fout, "%02X:", value->data[i]);
			fprintf(fout, "%02X\n", value->data[i]);
		}
	}
	EXIT();
}

static void dhcp_condserving(FILE *fout, int land, struct tr069_instance *cond)
{
	struct tr069_instance_node *cond_node;

	ENTER();

	for (cond_node = tr069_instance_first(cond);
	     cond_node != NULL;
	     cond_node = tr069_instance_next(cond, cond_node)) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i} */

		char minipbuf[INET_ADDRSTRLEN];
		char maxipbuf[INET_ADDRSTRLEN];
		char subnetbuf[INET_ADDRSTRLEN];
		const char *minip = NULL;
		const char *maxip = NULL;
		const char *subnet = NULL;

		const char *s;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.Enable */
		if (!tr069_get_bool_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_Enable))
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPLeaseTime */
		int ltime = tr069_get_int_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPLeaseTime);
		if (ltime >= 0 && ltime < 120)
			ltime = 120;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.MinAddress */
		minip = ip2str(tr069_get_ipv4_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_MinAddress), minipbuf);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.MaxAddress */
		maxip = ip2str(tr069_get_ipv4_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_MaxAddress), maxipbuf);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.SubnetMask */
		subnet = ip2str(tr069_get_ipv4_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_SubnetMask), subnetbuf);

		fprintf(fout, "dhcp-range=ld%dp%d,%s,%s,%s,",
			land, cond_node->instance, minipbuf, maxipbuf, subnetbuf);
		if (ltime < 0)
			fprintf(fout, "infinite\n");
		else
			fprintf(fout, "%d\n", ltime);

		/* FIXME: handle multiple DNS servers */
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DNSServers */
		s = tr069_get_string_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DNSServers);
		if (s && *s)
			fprintf(fout, "dhcp-option=net:ld%dp%d,option:%s,%s\n",
				land, cond_node->instance, "dns-server", s);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DomainName */
		s = tr069_get_string_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DomainName);
		if (s && *s)
			fprintf(fout, "dhcp-option=net:ld%dp%d,option:%s,%s\n",
				land, cond_node->instance, "domain-name", s);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.IPRouters */
		s = tr069_get_string_by_id(DM_TABLE(cond_node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_IPRouters);
		if (s && *s)
			fprintf(fout, "dhcp-option=net:ld%dp%d,option:%s,%s\n",
				land, cond_node->instance, "router", s);
	}
	EXIT();
}
#endif

int dnsmasq_config(void)
{
	FILE *fout;
	char wan_device[20];
        struct tr069_instance *ift;
        struct tr069_instance_node *node;

#if defined(WITH_DHCP_DNSMASQ)
	const char *domain = NULL;
#endif

	ENTER();

	fout = fopen(DNSMASQ_CONF, "w+");
	if (!fout) {
		EXIT();
		return -1;
	}

	fprintf(fout, "domain-needed\nbogus-priv\nexpand-hosts\n");
	fprintf(fout, "resolv-file=%s\n", RESOLV_CONF);

	wan_device[0] = '\0';

	/** VAR: InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enabled */
	if (tr069_get_bool_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							 cwmp__IGD_WANDevice,
							 1,
							 cwmp__IGD_WANDev_i_WANConnectionDevice,
							 1,
							 cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
							 1,
							 cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Enable, 0})) {
		strcpy(wan_device, PPP_DEVICE);
	}
	fprintf(fout, "except-interface=%s\n", wan_device);

#if defined(WITH_DHCP_DNSMASQ)
	fprintf(fout,
		"log-async=25\n"
		"dhcp-authoritative\n"
		"dhcp-lease-max=65536\n"
		"dhcp-option=46,4\n"
		"read-ethers\n"
		"leasefile-ro\n"
		"dhcp-leasefile=/var/run/dhcp.leases\n"
		"dhcp-script=/sbin/dnsmasqnotify\n");
#endif

	/** VAR: InternetGatewayDevice.LANDevice */
        ift = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								   cwmp__IGD_LANDevice, 0 });
	if (ift) {
#if defined(WITH_DHCP_DNSMASQ)
		unsigned int policy = 0;
#endif
                for (node = tr069_instance_first(ift);
                     node != NULL;
                     node = tr069_instance_next(ift, node)) {
			/** VAR: InternetGatewayDevice.LANDevice.{i} */

			struct tr069_value_table *hcm;
			struct tr069_instance *ipi;
			struct tr069_instance_node *ipi_node;

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
			hcm = tr069_get_table_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_LANHostConfigManagement);
			debug("(): hcm: %p\n", hcm);
			if (!hcm)
				continue;

#if defined(WITH_DHCP_DNSMASQ)
			const char *device;

			device = get_if_device((tr069_selector){ cwmp__InternetGatewayDevice,
						cwmp__IGD_LANDevice,
						node->instance, 0 });

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPServerEnable */
			if (tr069_get_bool_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPServerEnable)) {
				char minipbuf[INET_ADDRSTRLEN];
				char maxipbuf[INET_ADDRSTRLEN];
				char subnetbuf[INET_ADDRSTRLEN];
				const char *minip = NULL;
				const char *maxip = NULL;
				const char *subnet = NULL;

				const char *s;

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.X_TPLINO_NET_DHCPAllocationPolicy */
				policy |= tr069_get_enum_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_X_TPLINO_NET_DHCPAllocationPolicy);

				fprintf(fout, "interface=%s\n", device);
				if (!domain || !domain[0])
					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DomainName */
					domain = tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DomainName);

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPLeaseTime */
				int ltime = tr069_get_int_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPLeaseTime);
				if (ltime >= 0 && ltime < 120)
					ltime = 120;

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MinAddress */
				minip = ip2str(tr069_get_ipv4_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_MinAddress), minipbuf);
				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MaxAddress */
				maxip = ip2str(tr069_get_ipv4_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_MaxAddress), maxipbuf);
				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.SubnetMask */
				subnet = ip2str(tr069_get_ipv4_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_SubnetMask), subnetbuf);

				fprintf(fout, "dhcp-range=ld%d,%s,%s,%s,",
					node->instance, minipbuf, maxipbuf, subnetbuf);
				if (ltime < 0)
					fprintf(fout, "infinite\n");
				else
					fprintf(fout, "%d\n", ltime);

				/* FIXME: handle multiple DNS servers */
				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DNSServers */
				s = tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DNSServers);
				if (s && *s)
					fprintf(fout, "dhcp-option=net:ld%d,option:%s,%s\n",
						node->instance, "dns-server", s);

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DomainName */
				s = tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DomainName);
				if (s && *s)
					fprintf(fout, "dhcp-option=net:ld%d,option:%s,%s\n",
						node->instance, "domain-name", s);

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPRouters */
				s = tr069_get_string_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_IPRouters);
				if (s && *s)
					fprintf(fout, "dhcp-option=net:ld%d,option:%s,%s\n",
						node->instance, "router", s);


				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress */
				struct tr069_instance *staticIP = tr069_get_instance_ref_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStaticAddress);
				if (staticIP)
					dhcp_static(fout, node->instance, staticIP);

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption */
				struct tr069_instance *options = tr069_get_instance_ref_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPOption);
				if (options)
					dhcp_options(fout, node->instance, options);

				struct tr069_instance *cond;

				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool */
				cond = tr069_get_instance_ref_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool);
				if (cond)
					dhcp_condserving(fout, node->instance, cond);
 			}
#endif

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface */
			ipi = tr069_get_instance_ref_by_id(hcm, cwmp__IGD_LANDev_i_HostCfgMgt_IPInterface);
			if (ipi) {
				for (ipi_node = tr069_instance_first(ipi);
				     ipi_node != NULL;
				     ipi_node = tr069_instance_next(ipi, ipi_node)) {
					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i} */

					/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.Enable */
					if (tr069_get_bool_by_id(DM_TABLE(ipi_node->table),
								 cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_Enable)) {
						const char *dns;
						/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.X_TPOSS_DNSServers */
						dns = tr069_get_string_by_id(DM_TABLE(ipi_node->table),
									     cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_X_TPOSS_DNSServers);
						if (dns)
							fprintf(fout, "server=%s\n", dns);
					}
				}
			}
		}

#if defined(WITH_DHCP_DNSMASQ)
		if (!policy)
			fprintf(fout, "no-ping\n");
#endif
	}

#if defined(WITH_DHCP_DNSMASQ)
	if (!domain || !domain[0]) {
		fprintf(fout, "local=/%s/\n", domain);
		fprintf(fout, "domain=%s\n", domain);
	}
#endif

	fclose(fout);

	EXIT();
	return 0;
}

static unsigned char hexchar(const char c)
{
	switch (c) {
	case '0' ... '9':
		return c - '0';

	case 'A' ... 'F':
		return c - 'A' + 10;

	case 'a' ... 'f':
		return c - 'a' + 10;
	}
	return 0;
}

static unsigned char hex2bin(const char *s)
{
	return (hexchar(*s) << 4) + hexchar(*(s + 1));
}

static void tr069_set_hexbin_data_by_id(struct tr069_value_table *table, tr069_id id, char *s)
{
	char buf[255];
	char *p = buf;

	while (s && *s) {
		*p = hex2bin(s);
		p++; s+=2;
	}
	tr069_set_binary_data_by_id(table, id, p - buf, buf);
}

int dnsmasq_info(uint32_t diam_code, OBJ_GROUP *obj)
{
	OBJ_AVPINFO	header;
	int		af;
	struct in_addr	addr = { .s_addr = INADDR_NONE };
	char		*iface = NULL;
	char		*mac = NULL;
	char		*hostname = NULL;
	char		*clientid = NULL;
	char		*agentcircuitid = NULL;
	char		*agentremoteid = NULL;
	char		*subscriberid = NULL;
	char		*optlist = NULL;
	char		*optreqlist = NULL;
	time_t          expire = 0;

	ENTER();

	while(!diam_avpgrp_get_avp(obj->reqgrp, &header.code, &header.flags,
				   &header.vendor_id, &header.data, &header.len)) {
		debug(": CMD_GW: got %d", header.code);
		switch(header.code) {
		case AVP_DHCP_INTERFACE:
			if(!(iface = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			debug("iface: %s", iface);
			break;

		case AVP_DHCP_IPADDRESS:
			if(!diam_get_address_avp(&af, &addr, header.data) ||
			   af != AF_INET) {
				EXIT();
				return RC_SESSION_ERROR;
			}
			break;

		case AVP_DHCP_MACADDRESS:
			if(!(mac = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			debug("mac: %s", mac);
			break;

		case AVP_DHCP_CLIENT_ID:
			if(!(clientid = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_CIRCUIT_ID:
			if(!(agentcircuitid = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_REMOTE_ID:
			if(!(agentremoteid = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_SUBSCRIBER_ID:
			if(!(subscriberid = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_OPTLIST:
			if(!(optlist = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_OPTREQLIST:
			if(!(optreqlist = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_HOSTNAME:
			if(!(hostname = talloc_strndup(obj->req, header.data, header.len))) {
				EXIT();
				return RC_SERVER_ERROR;
			}
			break;

		case AVP_DHCP_EXPIRE:
			expire = diam_get_uint32_avp(header.data);
			break;

		case AVP_DHCP_REMAINING:
			expire = monotonic_time() + diam_get_uint32_avp(header.data);
			break;
		}
	}

	/* the source interface is required */
	if (!iface) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	/* map to logical LANDevice */

	struct tr069_instance *base;
	struct tr069_instance_node *d;
	tr069_selector *sel;

	base = get_if_layout(iface);
	if (!base) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	d = tr069_instance_first(base);
	if (!d) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
	sel = tr069_get_selector_by_id(DM_TABLE(d->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
	if (!sel) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	struct tr069_value_table *landev;
	struct tr069_value_table *hostst;
	struct tr069_instance *hostt;
	struct tr069_instance_node *node = NULL;

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	landev = tr069_get_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							      cwmp__IGD_LANDevice,
							      (*sel)[2], 0});
	if (!landev) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts */
	hostst = tr069_get_table_by_id(landev, cwmp__IGD_LANDev_i_Hosts);
	if (!hostst) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host */
		tr069_add_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							     cwmp__IGD_LANDevice,
							     (*sel)[2],
							     cwmp__IGD_LANDev_i_Hosts,
							     cwmp__IGD_LANDev_i_Hosts_Host, 0});
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts */
		hostst = tr069_get_table_by_id(landev, cwmp__IGD_LANDev_i_Hosts);
	}
	if (!hostst) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i} */
	hostt = tr069_get_instance_ref_by_id(hostst, cwmp__IGD_LANDev_i_Hosts_Host);
	debug(" hostt: %p", hostt);
	if (!hostt) {
		EXIT();
		return RC_SESSION_ERROR;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
	node = find_instance(hostt, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, T_IPADDR4, &init_DM_IP4(addr, 0));

	debug(" node: %p", node);

	switch(diam_code) {
	case CMD_DHCP_CLIENT_ACK: {
		struct tr069_value_table *t;
		int addr_src = cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource_None;

		if (!node) {
			tr069_id id = TR069_ID_AUTO_OBJECT;

			//hotspot_new_dhcp_lease(landev, sel, &lease, buf);

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i} */
			if ((node = tr069_add_instance_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
								cwmp__IGD_LANDevice,
								(*sel)[2],
								cwmp__IGD_LANDev_i_Hosts,
								cwmp__IGD_LANDev_i_Hosts_Host, 0}, &id)) == NULL)
				break;

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
			tr069_set_enum_by_id(DM_TABLE(node->table),
					     cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource,
					     cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_DHCP);

			addr_src = cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource_DHCP;
		} else {
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
			addr_src = tr069_get_enum_by_id(DM_TABLE(node->table),
							cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource) + 1;
		}

		t = DM_TABLE(node->table);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
		tr069_set_ipv4_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, addr);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
		tr069_set_enum_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource, 0);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.LeaseTimeRemaining */
		tr069_set_int_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining, expire);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.MACAddress */
		tr069_set_string_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_MACAddress, mac);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.HostName */
		tr069_set_string_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_HostName, hostname);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.InterfaceType */
		tr069_set_enum_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_InterfaceType, 0);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Active */
		tr069_set_bool_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_Active, 1);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.ClientID */
		tr069_set_hexbin_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_ClientID, clientid);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentCircuitId */
		tr069_set_hexbin_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentCircuitId, agentcircuitid);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
		tr069_set_hexbin_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentRemoteId, agentremoteid);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
		tr069_set_hexbin_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_SubScriberId, subscriberid);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPRequestOptionList */
		tr069_set_hexbin_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPRequestOptionList, optlist);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPParameterRequestList */
		tr069_set_hexbin_data_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPParameterRequestList, optreqlist);

		update_instance_node_index(node);
		hs_update_client_by_device(landev->id, addr_src, addr, mac, NULL, NULL, NULL,
					   /** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentCircuitId */
					   tr069_get_binary_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentCircuitId),
					   /** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
					   tr069_get_binary_by_id(t, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentRemoteId),
					   t->id, time2ticks(expire));
		break;
	}
	case CMD_DHCP_CLIENT_RELEASE:
	case CMD_DHCP_CLIENT_EXPIRE:
		if (!node)
			break;

		hs_remove_client_by_device(landev->id, addr, 0);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i} */
		tr069_del_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
					cwmp__IGD_LANDevice,
					(*sel)[2],
					cwmp__IGD_LANDev_i_Hosts,
					cwmp__IGD_LANDev_i_Hosts_Host,
					node->instance, 0});

		break;
	}


/* */
	EXIT();
	return 0;
}

#if defined(WITH_DHCP_DNSMASQ)

int start_dhcpd(const char *device __attribute__ ((unused)),
		const tr069_selector sel __attribute__ ((unused)))
{
	return 0;
}

void stop_dhcpd(const char *device __attribute__ ((unused)))
{
}
#endif
