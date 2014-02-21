#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <sys/types.h>

#define SDEBUG 1
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#include "ifup.h"
#include "process.h"

int vlan_up(const char *device, int tag, const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	char fname[128];

	ENTER();

	debug("(): dev: %s, tag: %d, sel: %s\n", device, tag, sel2str(b1, sel));
	snprintf(fname, sizeof(fname), "%s.%d", device, tag);
	if_add2ifmap(fname, sel);

	vasystem("vconfig add %s %d", device, tag);

	EXIT();
	return 0;
}

int vlan_down(const char *device, const struct tr069_instance_node *vnode)
{
	ENTER();

	debug("(): dev: %s", device);

	vasystem("vconfig rem %s", device);
	/*ifmap_remove_if_by_ref(vnode);*/

	EXIT();
	return 0;
}

int vlan_if_setup(const char *device, const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct tr069_value_table *vlt;
	tr069_selector *if_sel;
	unsigned int tag;

	ENTER();

	debug(": sel: %s", sel2str(b1, sel));
	/** InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i} */
	if (sel[1] != cwmp__IGD_X_TPOSS_VLAN ||
	    sel[2] != cwmp__IGD_VLAN_VLANs ||
	    sel[3] == 0 ||
	    sel[4] != 0) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i} */
	vlt = tr069_get_table_by_selector(sel);
	if (!vlt) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Tag */
	tag = tr069_get_uint_by_id(vlt, cwmp__IGD_VLAN_VLANs_i_Tag);

	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Device */
	if_sel = tr069_get_selector_by_id(vlt, cwmp__IGD_VLAN_VLANs_i_Device);
	if (if_sel)
		vlan_up(device, tag, *if_sel);

	EXIT();
	return 0;
}

void vlan_setup(const char *device, const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128], b2[128];
#endif
	struct tr069_instance *vl_map;
	struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs */
	vl_map = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								      cwmp__IGD_X_TPOSS_VLAN,
								      cwmp__IGD_VLAN_VLANs, 0} );

	if (!vl_map) {
		fprintf(stderr, "couldn't get VLAN map from storage\n");
		EXIT();
		return;
	}

        for (node = tr069_instance_first(vl_map);
             node != NULL;
             node = tr069_instance_next(vl_map, node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i} */

		tr069_selector *if_sel;
		unsigned int tag;

		/** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Device */
		if_sel = tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_VLAN_VLANs_i_Device);
		if (!if_sel)
			continue;

		debug("(): dev: %s, sel: %s ?? %s\n", device, sel2str(b1, sel), sel2str(b2, *if_sel));

		if (tr069_selcmp(*if_sel, sel, TR069_SELECTOR_LEN) != 0)
			continue;

                /** VAR: InternetGatewayDevice.X_TPOSS_VLAN.VLANs.{i}.Tag */
                tag = tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_VLAN_VLANs_i_Tag);

                vlan_up(device, tag, *if_sel);
	}
	EXIT();
	return;
}

void del_IGD_VLAN_VLANs(const struct tr069_table *kw __attribute__ ((unused)),
				  tr069_id id __attribute__ ((unused)),
				  struct tr069_instance *inst __attribute__ ((unused)),
				  struct tr069_instance_node *node)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	const struct tr069_value_table *vt = DM_TABLE(node->table);
	const struct tr069_instance_node *ifn;
	const tr069_selector *vsel;
	const char *device;

	ENTER();

	if (!vt)
		goto out;

	if (!(vsel = &vt->id))
		goto out;

	debug("(): Deleting VLAN: %s", tr069_sel2name(*vsel, b1, sizeof(b1)));

	if (!(vsel = tr069_get_selector_by_id(vt, cwmp__IGD_VLAN_VLANs_i_Device)))
		goto out;
	debug("(): Searching map for: %s", tr069_sel2name(*vsel, b1, sizeof(b1)));

	if (!(ifn = get_interface_node_by_selector(*vsel)))
		goto out;
	if (!(device = tr069_get_string_by_id(DM_TABLE(ifn->table), cwmp__IGD_IfMap_If_i_Name)))
		goto out;
	debug("(): About to destroy interface: %s", device);

	vlan_down(device, ifn);

out:
	EXIT();
}

/*
void dm_vlan_reconf_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct tr069_value_table *vtab;

	debug("(): Setting up VLAN for %s.", tr069_sel2name(sel, b1, sizeof(b1)));

	if(!(vtab = tr069_get_table_by_selector(sel)))
		return;

return;
}
*/
