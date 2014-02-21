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

#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdio.h>
#include <net/if.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_action.h"

#define SDEBUG
#include "debug.h"

#include "process.h"
#include "bitmap.h"
#include "ifup.h"
#include "l3forward.h"

#define BLOCK_ALLOC	(bits_size * 16)

#define TABLE_OFFSET	3
#define PRIORITY_OFFSET	1024

static size_t policy_size = 0;
static int *policies = NULL;
static bits_t *policy_map = NULL;

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
}

static void grow_policy_map(size_t size)
{
	size_t bytes = size / bits_size;
	if (!policy_map) {
		policy_map = malloc(bytes);
		memset(policy_map, 0, bytes);

		policies = malloc(sizeof(int) * size);
		memset(policies, -1, sizeof(int) * size);

		policy_size = size;
	}
	else if (policy_size < size) {
		size_t old_bytes = policy_size / bits_size;

		policy_map = realloc(policy_map, old_bytes + bytes);
		memset(policy_map + old_bytes, 0, bytes);

		policies = realloc(policies, sizeof(int) * (policy_size + size));
		memset(policies + policy_size, -1, sizeof(int) * size);

		policy_size += size;
	}
}

static int find_l3_policy(int policy)
{
	ENTER();

	if (!policies) {
		EXIT();
		return -1;
	}

	for (int i = 0; i < (int)policy_size; i++) {
		if (policies[i] == policy) {
			debug(": got: %d", i);
			EXIT();
			return i;
		}
	}

	EXIT();
	return -1;
}

static int add_l3_policy(int policy)
{
	int ret;

	if (!policy_map)
		grow_policy_map(BLOCK_ALLOC);

	ret = map_ffz(policy_map, policy_size / bits_size);
	if (ret < 0) {
		grow_policy_map(BLOCK_ALLOC);
		ret = map_ffz(policy_map, policy_size / bits_size);
	}
	if (ret >= 0) {
		map_set_bit(policy_map, ret);
		policies[ret] = policy;
	}

	return ret;
}

/* FIXME: migth need a tree instead */
int register_l3_policy(int policy, int base, uint32_t fwmark, uint32_t mask)
{
	int ret;

	ENTER(": policy: %d, base priority: %d, fwmark: %x, mask: %x",
	      policy, base, fwmark, mask);

	ret = find_l3_policy(policy);
	if (ret < 0)
		ret = add_l3_policy(policy);
	if (ret < 0) {
		EXIT();
		return ret;
	}

	vasystem("ip rule add fwmark 0x%x/0x%x priority %d table %d",
		 fwmark, mask, base + PRIORITY_OFFSET, ret + TABLE_OFFSET);

	EXIT_MSG(": reg: %d", ret);
	return ret;
}

/* FIXME: maybe use reference counters to determine when to remove a policy from the policy map
 * however, using the current combination of deletion hooks _and_ actions a correct
 * policy cannot be passed to this function anyway */
int unregister_l3_policy(int policy __attribute__((unused)),
			 int base, uint32_t fwmark, uint32_t mask)
{
	ENTER(": base priority: %d, fwmark: %x, mask: %x", base, fwmark, mask);

	vasystem("ip rule del fwmark 0x%x/0x%x priority %d",
		 fwmark, mask, base + PRIORITY_OFFSET);

	EXIT();
	return 0;
}

void if_routes(const char *device, const tr069_selector sel)
{
	int mlen;
        struct tr069_instance *l3fw;
        struct tr069_instance_node *node;

#if defined(SDEBUG)
	char b1[128], b2[128];
#endif

	ENTER();

	debug("(): dev: %s, sel: %s\n", device, sel2str(b1, sel));

	/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding */
	l3fw = tr069_get_instance_ref_by_selector((tr069_selector) { cwmp__InternetGatewayDevice,
				cwmp__IGD_Layer3Forwarding,
				cwmp__IGD_L3Fwd_Forwarding, 0 });
	if (!l3fw) {
		EXIT();
		return;
	}

	for (node = tr069_instance_first(l3fw);
	     node != NULL;
	     node = tr069_instance_next(l3fw, node)) {
		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i} */

		struct tr069_value_table *l3r = DM_TABLE(node->table);
		tr069_selector *r3dev;
		int l3policy, table;
		char tab_spec[32] = "";
		char via_spec[32] = "";
		char dst_spec[32] = "";
		char gwbuf[INET_ADDRSTRLEN];
		struct in_addr dstip;
		struct in_addr dstmsk;
		struct in_addr srcip;
		struct in_addr srcmsk;
		struct in_addr gwip;

		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.Enable */
		if (!tr069_get_bool_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_Enable))
			continue;

		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.Interface */
		r3dev = tr069_get_selector_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_Interface);
		if (!r3dev)
			continue;

		debug("(): r3dev: %s\n", sel2str(b2, *r3dev));

		if (tr069_selcmp(sel, *r3dev, TR069_SELECTOR_LEN) != 0)
			continue;

		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.ForwardingPolicy */
		l3policy = tr069_get_int_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_ForwardingPolicy);
		debug(": policy: %d", l3policy);
		if (l3policy > 0) {
			table = find_l3_policy(l3policy);
			if (table < 0)
				table = add_l3_policy(l3policy);

			debug(": table: %d", table);

			if (table >= 0)
				snprintf(tab_spec, sizeof(tab_spec), "table %d ", table + TABLE_OFFSET);
			debug(": tab_spec: -%s-", tab_spec);
		}

		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.DestIPAddress */
		dstip = tr069_get_ipv4_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_DestIPAddress);
		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.DestSubnetMask */
		dstmsk = tr069_get_ipv4_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_DestSubnetMask);

		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.SourceIPAddress */
		srcip = tr069_get_ipv4_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_SourceIPAddress);
		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.SourceSubnetMask */
		srcmsk = tr069_get_ipv4_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_SourceSubnetMask);

		/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.GatewayIPAddress */
		gwip = tr069_get_ipv4_by_id(l3r, cwmp__IGD_L3Fwd_Fwd_i_GatewayIPAddress);

		if (gwip.s_addr != INADDR_ANY &&
		    gwip.s_addr != INADDR_NONE &&
		    ip2str(gwip, gwbuf))
			snprintf(via_spec, sizeof(via_spec), "via %s ", gwbuf);

		if (dstip.s_addr == INADDR_ANY &&
		    dstmsk.s_addr == INADDR_ANY) {
			strncpy(dst_spec, "default", sizeof(dst_spec));
		} else {
			char dstbuf[INET_ADDRSTRLEN];

			if (dstmsk.s_addr == INADDR_ANY ||
			    dstmsk.s_addr == INADDR_NONE) {
				mlen = 32;
			} else {
				debug("s_addr: %x, %x\n", dstmsk.s_addr, ntohl(dstmsk.s_addr));
				mlen = 33 - ffs(ntohl(dstmsk.s_addr));
			}
			snprintf(dst_spec, sizeof(dst_spec), "%s/%d", ip2str(dstip, dstbuf), mlen);
		}

		//ip route add 192.168.0.0/24 via 10.194.45.125 dev br0
		vasystem("ip route add %s %s%s dev %s",
			 dst_spec, tab_spec, via_spec, device);
	}
	EXIT();
}

void del_IGD_L3Fwd_Forwarding(const struct tr069_table *kw __attribute__((unused)),
			      tr069_id id __attribute__((unused)),
			      struct tr069_instance *inst __attribute__((unused)),
			      struct tr069_instance_node *node)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	tr069_selector *dev_sel;

	ENTER(": execute for sel: %s", sel2str(b1, DM_TABLE(node->table)->id));

	/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.Interface */
	dev_sel = tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_L3Fwd_Fwd_i_Interface);
	if (!dev_sel) {
		EXIT_MSG(": no interface in forwarding rule");
		return;
	}

	devrestart(*dev_sel);

	EXIT();
}

void dm_l3_reload_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	tr069_selector *dev_sel;

	ENTER(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	if (type == DM_DEL) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.Layer3Forwarding.Forwarding.{i}.Interface */
	dev_sel = tr069_get_selector_by_selector((tr069_selector) {
		sel[0], sel[1], sel[2], sel[3],
		cwmp__IGD_L3Fwd_Fwd_i_Interface, 0
	});
	if (!dev_sel) {
		EXIT_MSG(": no interface in forwarding rule");
		return;
	}

	devrestart(*dev_sel);

	EXIT();
}

#if 0
void if_flush_routes(const char *device)
{
	debug(": removing all routing entrys for device %s.", device);
	vasystem("ip route flush dev %s", device);
}
#endif

