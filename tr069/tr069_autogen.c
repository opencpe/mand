#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "tr069_autogen.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "ifup.h"

#define E_INITIAL_MEMBERS		16

auto_default_store def_store;

int init_auto_default_store(void)
{
	if ((def_store.storage = malloc(E_INITIAL_MEMBERS * sizeof(auto_default_val))) == NULL)
		return 0;

	def_store.members = 0;
	def_store.max_mbrs = E_INITIAL_MEMBERS;

	return 1;
}

int enlarge_auto_default_store(void)
{
	if ((def_store.storage = realloc(def_store.storage, (def_store.max_mbrs + E_INITIAL_MEMBERS) * sizeof(auto_default_val))) == NULL)
		return 0;

	def_store.max_mbrs = def_store.max_mbrs + E_INITIAL_MEMBERS;

	return 1;
}

int add_auto_default_entry(struct tr069_value_table *ift, tr069_id id, int e_type)
{
	if (def_store.members >= def_store.max_mbrs)
		if(!enlarge_auto_default_store())
			return 0;

	tr069_selcpy(def_store.storage[def_store.members].entry, ift->id);
	tr069_selcat(def_store.storage[def_store.members].entry, id);
	def_store.storage[def_store.members].type  = e_type;
	def_store.members++;

	return 1;
}

const char *gen_dev_name(void)
{
	const char *mdl_nm;
	char *ret, *pos;

	/** VAR: InternetGatewayDevice.DeviceInfo.ModelName */
	tr069_selector sel = { cwmp__InternetGatewayDevice,
	cwmp__IGD_DeviceInfo,
	cwmp__IGD_DevInf_ModelName, 0 };

	mdl_nm = tr069_get_string_by_selector(sel);
	ret = strdup(mdl_nm);

	pos = ret;
	while (*pos) {
		if (*pos == ' ')
			*pos = '_';
		pos++;
	}

	return (const char *)ret;
}

int generate_auto_defaults(const char *mac_addr)
{
	const char *dev_name = gen_dev_name();
	char *mac_id = NULL;
	char buf[128];
	int stor[3], i, ssids = 0;

	sscanf(mac_addr, "%*x:%*x:%*x:%x:%x:%x", stor, stor+1, stor+2);
	asprintf(&mac_id, "%02x%02x%02x", *stor, stor[1], stor[2]);

	for(i = 0; i < def_store.max_mbrs && i < def_store.members; i++) {
		switch(def_store.storage[i].type) {
			case AG_HNAME:
			case AG_CWMPUN:
				snprintf(buf, sizeof(buf) - 1, "%s-%s", dev_name, mac_id);
			break;
			case AG_SSID:
				if(!ssids) {
					snprintf(buf, sizeof(buf) - 1, "%s-%s", dev_name, mac_id);
					ssids = 2;
				}
				else
					snprintf(buf, sizeof(buf) - 1, "%s-%s-%d", dev_name, mac_id, ssids++);
			break;
			case AG_TNLNM:
				snprintf(buf, sizeof(buf) - 1, "%s-%s%s", dev_name, mac_id, "@lngdefault");
			break;
			default:
				*buf = 0;
		}
		if(*buf)
			tr069_set_string_by_selector(def_store.storage[i].entry, buf, DV_UPDATED);
	}

	free(dev_name);
	free(mac_id);

	return 1;
}

