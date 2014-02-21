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

#include <assert.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#define SDEBUG
#include "debug.h"

#include "if_device.h"

static int in_same_network(struct in_addr a, struct in_addr b, struct in_addr netmask)
{
	return ((a.s_addr & netmask.s_addr)  == (b.s_addr & netmask.s_addr));
}

int is_local_ip(struct tr069_value_table *land, struct in_addr ip)
{
	struct tr069_value_table *lhcm;
        struct tr069_instance *ipif;
        struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
	lhcm = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_LANHostConfigManagement);
	if (!lhcm) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface */
	ipif = tr069_get_instance_ref_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_IPInterface);
	if (!ipif) {
		EXIT();
		return 0;
	}

        for (node = tr069_instance_first(ipif);
             node != NULL;
             node = tr069_instance_next(ipif, node))
	{
		struct in_addr ifip;
		struct in_addr mask;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.Enable */
		if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_Enable))
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceIPAddress */
		ifip = tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceIPAddress);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceSubnetMask */
		mask = tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceSubnetMask);

		if (in_same_network(ip, ifip, mask)) {
			EXIT();
			return 1;
		}
	}

	EXIT();
	return 0;
}

