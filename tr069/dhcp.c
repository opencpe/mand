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

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#define SDEBUG
#include "debug.h"

#include "ifup.h"
#include "dhcp.h"


static const struct tr069_value_table *find_dhcp_entry_by_addr(const tr069_selector sel, struct in_addr addr)
{
	struct tr069_instance *hostt;
	struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host */
	hostt = tr069_get_instance_ref_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							     cwmp__IGD_LANDevice,
							     sel[2],
							     cwmp__IGD_LANDev_i_Hosts,
	      						     cwmp__IGD_LANDev_i_Hosts_Host, 0});
	if (!hostt) {
		EXIT();
		return NULL;
	}


	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i].IPAddress */
	node = find_instance(hostt, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, T_IPADDR4, &init_DM_IP4(addr, 0));
	if (node) {
		EXIT();
		return DM_TABLE(node->table);
	}

	EXIT();
	return NULL;
}

/* FIXME: use device to find the correct LAN Device */

const binary_t *dhcp_get_circuit_id(const char *device __attribute__ ((unused)), struct in_addr addr)
{
	const binary_t *ret;
	struct tr069_value_table *entry;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.1 */
	entry = find_dhcp_entry_by_addr((tr069_selector){cwmp__InternetGatewayDevice,
							 cwmp__IGD_LANDevice,
							 1, 0}, addr);
	if (!entry) {
		EXIT();
		return NULL;
	}
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentCircuitId */
	ret = tr069_get_binary_by_id(entry, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentCircuitId);

	EXIT();
	return ret;
}

const binary_t *dhcp_get_remote_id(const char *device __attribute__ ((unused)), struct in_addr addr)
{
	const binary_t *ret;
	struct tr069_value_table *entry;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.1 */
	entry = find_dhcp_entry_by_addr((tr069_selector){cwmp__InternetGatewayDevice,
							 cwmp__IGD_LANDevice,
							 1, 0}, addr);
	if (!entry) {
		EXIT();
		return NULL;
	}
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
	ret = tr069_get_binary_by_id(entry, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentRemoteId);

	EXIT();
	return ret;
}

static void renumber_pool_order(struct tr069_instance *dhcps)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct tr069_instance_node *node;
	unsigned int i = 1;

        for (node = tr069_instance_first_idx(dhcps, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder);
             node != NULL;
             node = tr069_instance_next_idx(dhcps, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, node)) {
		debug(": renumbering %s to %d", sel2str(b1, DM_TABLE(node->table)->id), i);
		tr069_set_uint_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, i++);
	}
}

void add_IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool(const struct tr069_table *kw __attribute__ ((unused)),
							    tr069_id id __attribute__ ((unused)),
							    struct tr069_instance *inst,
							    struct tr069_instance_node *node)
{
	struct tr069_value_table *dhcpt = DM_TABLE(node->table);
	struct tr069_instance_node *last;
	unsigned int order = 1;

	last = tr069_instance_last_idx(inst, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder);
	if (last)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.PoolOrder */
		order = tr069_get_uint_by_id(DM_TABLE(last->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder) + 1;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.PoolOrder */
	tr069_set_uint_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, order);
	update_index(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, node);
}


void del_IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder(const struct tr069_table *kw __attribute__ ((unused)),
							tr069_id id __attribute__ ((unused)),
							struct tr069_instance *inst,
							struct tr069_instance_node *node __attribute__ ((unused)))
{
	renumber_pool_order(inst);
}

int set_IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder(struct tr069_value_table *base,
						       tr069_id id __attribute__ ((unused)),
						       const struct tr069_element *elem __attribute__ ((unused)),
						       DM_VALUE *st,
						       DM_VALUE val)
{
	struct tr069_instance_node *node = cast_table2node(base);
	struct tr069_instance dhcps = { .instance = node->root };
	struct tr069_instance_node *e;

	ENTER(", base: %p, node: %p, instance: %p", base, node, dhcps.instance);

	dm_assert(dhcps.instance != NULL);

	e = find_instance(&dhcps, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, T_UINT, &val);
	debug(": find_instance(%d): %p", DM_UINT(val), e);
	if (e && e != node) {
		/*
		 * new PoolOrder is already taken and it's no us
		 */

		while (e) {
			/* increasing the PoolOrder will not alter the index order */

			if (node != e)
				/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.PoolOrder */
				tr069_set_uint_by_id(DM_TABLE(e->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder,
						     tr069_get_uint_by_id(DM_TABLE(e->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder) + 1);

			e = tr069_instance_next_idx(&dhcps, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, e);
		}
	}
	set_DM_UINT(*st, DM_UINT(val));

	update_index(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, node);

	renumber_pool_order(&dhcps);

	EXIT();
	return 1;
}
