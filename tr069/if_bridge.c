#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_bridge.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

//#define SDEBUG
#include "debug.h"
#include "process.h"
#include "ifup.h"

static struct tr069_instance *br_map;

#define brctl(format, ...) vasystem("/usr/sbin/brctl " format, ## __VA_ARGS__)

const char *get_br_device(const tr069_selector sel)
{
	struct tr069_instance_node *node;
	const char *ret = NULL;

	if (!br_map || !sel)
		return NULL;

	pthread_rwlock_rdlock(&tr069_rwlock);
        for (node = tr069_instance_first(br_map);
             node != NULL;
             node = tr069_instance_next(br_map, node)) {
		tr069_selector *br_sel;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Layer2Bridge.{i}.DeviceReference */
		br_sel = tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_L2Bridge_i_DeviceReference);
		if (tr069_selcmp(*br_sel, sel, TR069_SELECTOR_LEN) == 0) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Layer2Bridge.{i}.Name */
			ret = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_L2Bridge_i_Name);
			break;
		}
	}
	pthread_rwlock_unlock(&tr069_rwlock);

	return ret;
}

int br_addif(const char *br, const char *device)
{
	return brctl("addif %s %s", br, device);
}

static int _br_create_if(struct tr069_instance_node *node)
{
	struct tr069_value_table *ift = DM_TABLE(node->table);
	struct tr069_value_table *stp;
	const char *device;
	unsigned int val;

	ENTER();

	device = tr069_get_string_by_id(ift, cwmp__IGD_IfMap_L2Bridge_i_Name);

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Layer2Bridge.{i}.DeviceReference */
	_if_add2ifmap(device, *tr069_get_selector_by_id(ift, cwmp__IGD_IfMap_L2Bridge_i_DeviceReference));

	brctl("addbr %s", device);

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.AddressAgingTime */
	val = tr069_get_uint_by_id(ift, cwmp__IGD_IfMap_L2Bridge_i_AddressAgingTime);
	if (val)
		brctl("%s %s %d", "setageingtime", device, val);

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.GarbageCollectionInterval */
	val = tr069_get_uint_by_id(ift, cwmp__IGD_IfMap_L2Bridge_i_GarbageCollectionInterval);
	if (val)
		brctl("%s %s %d", "setgcint", device, val);

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.SpanningTree */
	stp = tr069_get_table_by_id(ift, cwmp__IGD_IfMap_L2Bridge_i_SpanningTree);
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.SpanningTree.Enabled */
	if (stp && tr069_get_bool_by_id(stp, cwmp__IGD_IfMap_L2Bridge_i_Stp_Enabled)) {

		brctl("stp %s %s", device, "on");

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.SpanningTree.Priority */
		val = tr069_get_uint_by_id(stp, cwmp__IGD_IfMap_L2Bridge_i_Stp_Priority);
		if (val)
			brctl("%s %s %d", "setbridgeprio", device, val);

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.SpanningTree.ForwardDelay */
		val = tr069_get_uint_by_id(stp, cwmp__IGD_IfMap_L2Bridge_i_Stp_ForwardDelay);
		if (val)
			brctl("%s %s %d", "setfd", device, val);

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.SpanningTree.MaxMessageAge */
		val = tr069_get_uint_by_id(stp, cwmp__IGD_IfMap_L2Bridge_i_Stp_MaxMessageAge);
		if (val)
			brctl("%s %s %d", "setmaxage", device, val);

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.SpanningTree.HelloTime */
		val = tr069_get_uint_by_id(stp, cwmp__IGD_IfMap_L2Bridge_i_Stp_HelloTime);
		if (val)
			brctl("%s %s %d", "hello", device, val);

	} else
		brctl("stp %s %s", device, "off");

	if_linkup(device);

	EXIT();
	return 0;
}

int find_port4mac(const char *brname, u_int8_t mac_addr[6])
{
#define CHUNK 128
        int i, n;
	int r = -1;
	int sock;
        struct __fdb_entry fdb[CHUNK];
        int offset = 0;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

        for(;;) {
                unsigned long args[] = { BRCTL_GET_FDB_ENTRIES, (unsigned long)fdb, CHUNK, offset };
                struct ifreq ifr;
                int retries = 0;

                strncpy(ifr.ifr_name, brname, IFNAMSIZ);
                ifr.ifr_data = (char *)args;

        retry:
                n = ioctl(sock, SIOCDEVPRIVATE, &ifr);
                if (n < 0 && errno == EAGAIN && ++retries < 10) {
                        sleep(0);
                        goto retry;
                }

                if (n == 0)
                        break;

                if (n < 0) {
                        debug(": read of forward table failed: %s\n", strerror(errno));
			goto out;
                }

                offset += n;

                for (i = 0; i < n; i++)
                        if (memcmp(fdb[i].mac_addr, mac_addr, 6) == 0) {
                                r = fdb[i].port_no;
				goto out;
                        }
        }
 out:
	close(sock);
        return r;
}

void br_init(struct tr069_value_table *ift)
{
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Layer2Bridge */
	br_map = tr069_get_instance_ref_by_id(ift, cwmp__IGD_IfMap_Layer2Bridge);
	if (br_map) {
		struct tr069_instance_node *node;

		pthread_rwlock_rdlock(&tr069_rwlock);

		for (node = tr069_instance_first(br_map);
		     node != NULL;
		     node = tr069_instance_next(br_map, node))
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Layer2Bridge.{i} */
			_br_create_if(node);

		pthread_rwlock_unlock(&tr069_rwlock);
	}
}
