#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "routers.h"

//#define SDEBUG 1
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#include "ifup.h"
#include "process.h"
#include "board_support.h"

#ifdef HAVE_LIBNVRAM
#include "nvram.h"
#endif

static int get_offs_from_vl_map(struct tr069_instance *vl_map, const unsigned int tag)
{
	struct tr069_instance_node *node;

        for (node = tr069_instance_first(vl_map);
             node != NULL;
             node = tr069_instance_next(vl_map, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Tag */
		if (tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_VLAN_VLANs_i_Tag) == tag)
			return node->instance - 1;
	}
	return -1;
}

static struct tr069_value_table *get_tag_from_selector(struct tr069_instance *vl_map, const tr069_selector sel)
{
	struct tr069_value_table *ret;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i} */
	if (sel[1] != cwmp__IGD_X_TPOSS_VLAN ||
	    sel[2] != cwmp__IGD_VLAN_VLANs ||
	    sel[3] == 0) {
		EXIT();
		return NULL;
	}

	ret = tr069_get_instance_by_id(vl_map, sel[3]);
	if (!ret)
		debug("(): %d == %d\n", sel[3], tr069_get_uint_by_id(ret, cwmp__IGD_VLAN_VLANs_i_Tag));

	EXIT();
	return ret;
}

int switch_setup(const char *device, const tr069_selector sel)
{
	int i;
	char *vlcfg;
	char fname[128];
	struct tr069_instance_node *node;
	const unsigned char *v_map = get_switch_mapping();

	struct tr069_instance *sw_map;
	struct tr069_instance *vl_map;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPOSS_Switch */
	if (sel[1] != cwmp__IGD_X_TPOSS_Switch ||
	    sel[2] == 0) {
		EXIT();
		return -1;
	}

	if (!v_map) {
		EXIT();
		return -1;
	}

	/* make sure the device is actually up */
	if_linkup(device);

	load_switch_driver();

	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN */
	vl_map = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								      cwmp__IGD_X_TPOSS_VLAN,
								      cwmp__IGD_VLAN_VLANs, 0} );
	if (!vl_map) {
		fprintf(stderr, "couldn't get VLAN map from storage\n");
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap */
	sw_map = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								      cwmp__IGD_X_TPOSS_Switch,
								      sel[2],
								      cwmp__IGD_Switch_i_PortMap, 0 });
	if (!sw_map) {
		fprintf(stderr, "couldn't get SwitchMap from storage\n");
		EXIT();
		return -1;
	}

	int size = 16;

	vlcfg = malloc(128 * size);
	if (!vlcfg) {
		EXIT();
		return -1;
	}

	memset(vlcfg, 0, 128 * size);

        for (node = tr069_instance_first(sw_map), i = 0;
             node != NULL;
             node = tr069_instance_next(sw_map, node), i++) {
		/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i} */

		unsigned int tag;
		int offs, l;
		struct tr069_instance *vt_map;
		struct tr069_instance_node *vt_node;
		const struct tr069_value_table *vlan;

		/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.VLAN */
		vlan = get_tag_from_selector(vl_map,
					     *tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_Switch_i_SWPortMap_j_VLAN));
		if (!vlan)
			continue;

		/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.VLAN.VLANs.{i}.Tag */
		tag = tr069_get_uint_by_id(vlan, cwmp__IGD_VLAN_VLANs_i_Tag);
		offs = get_offs_from_vl_map(vl_map, tag);
		if (offs < 0)
			continue;

		offs *= 128;
		l = strlen(&vlcfg[offs]);

		if (l > 0) {
			vlcfg[offs + l] = ' ';
			l++;
		}
		snprintf(&vlcfg[offs + l], 127 - l, "%d", v_map[node->instance]);

		/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.TaggedVLAN */
		vt_map = tr069_get_instance_ref_by_id(DM_TABLE(node->table), cwmp__IGD_Switch_i_SWPortMap_j_TaggedVLAN);
		if (!vt_map)
			continue;

		for (vt_node = tr069_instance_first(vt_map);
		     vt_node != NULL;
		     vt_node = tr069_instance_next(vt_map, vt_node)) {
			/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.TaggedVLAN.{i} */
			/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.TaggedVLAN.{i}.VLAN */
			vlan = get_tag_from_selector(vl_map,
						     *tr069_get_selector_by_id(DM_TABLE(vt_node->table), cwmp__IGD_Switch_i_SWPortMap_j_PortVLan_k_VLAN));
			if (!vlan)
				continue;

			/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.VLAN.VLANs.{i}.Tag */
			tag = tr069_get_uint_by_id(vlan, cwmp__IGD_VLAN_VLANs_i_Tag);
			offs = get_offs_from_vl_map(vl_map, tag);
			if (offs < 0)
				continue;

			offs *= 128;
			l = strlen(&vlcfg[offs]);

			if (l > 0) {
				vlcfg[offs + l] = ' ';
				l++;
			}
			snprintf(&vlcfg[offs + l], 127 - l, "%dt", v_map[node->instance]);
		}
	}

	snprintf(fname, sizeof(fname), "/proc/switch/%s/%s", device, "reset");
	sys_echo(fname, "%d", 1);
	debug("(): %s <- 1\n", fname);

	snprintf(fname, sizeof(fname), "/proc/switch/%s/%s", device, "enable");
	sys_echo(fname, "%d", 0);
	debug("(): %s <- 0\n", fname);

	snprintf(fname, sizeof(fname), "/proc/switch/%s/%s", device, "enable_vlan");
	sys_echo(fname, "%d", 1);
	debug("(): %s <- 1\n", fname);

	for (node = tr069_instance_first(vl_map), i = 0;
	     node != NULL;
	     node = tr069_instance_next(vl_map, node), i++) {
		unsigned int tag;

		if (vlcfg[i*128]) {
			/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Tag */
			tag = tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_VLAN_VLANs_i_Tag);

			debug("(): %d: %s %dt\n", tag, &vlcfg[i*128], v_map[0]);

			snprintf(fname, sizeof(fname), "/proc/switch/%s/vlan/%d/ports", device, tag);
			sys_echo(fname, "%s %dt", &vlcfg[i*128], v_map[0]);
			debug("(): %s <- %s %dt\n", fname, &vlcfg[i*128], v_map[0]);

			/** VAR: InternetGatewayDevice.X_TPOSS_Switch.{i}.PortMap.{i}.VLAN.VLANs.{i}.Device */
			vlan_up(device, tag, *tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_VLAN_VLANs_i_Device));
		}
	}

	snprintf(fname, sizeof(fname), "/proc/switch/%s/%s", device, "enable");
	sys_echo(fname, "%d", 1);

	EXIT();
	return 0;
}
