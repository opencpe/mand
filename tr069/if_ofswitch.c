#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

//#define SDEBUG
#include "debug.h"
#include "process.h"
#include "ifup.h"

#define OVS_OPENFLOWD	"/usr/bin/ovs-openflowd"

#define ERL_BIN		"/usr/bin/erl"
#define FLSC_VERSION	"0.1-1"

static int flsc_id = -1;

static struct tr069_instance *dp_map;

#define dpctl(format, ...) vasystem("/usr/bin/ovs-dpctl " format, ## __VA_ARGS__)

const char *
get_ofs_device(const tr069_selector sel)
{
	const char *ret = NULL;

	if (!dp_map || !sel)
		return NULL;

	pthread_rwlock_rdlock(&tr069_rwlock);
        for (struct tr069_instance_node *node = tr069_instance_first(dp_map);
             node != NULL;
             node = tr069_instance_next(dp_map, node)) {
		tr069_selector *dp_sel;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i}.DeviceReference */
		dp_sel = tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_OFSwitch_i_DeviceReference);
		if (tr069_selcmp(*dp_sel, sel, TR069_SELECTOR_LEN) == 0) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i}.Name */
			ret = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_IfMap_OFSwitch_i_Name);
			break;
		}
	}
	pthread_rwlock_unlock(&tr069_rwlock);

	return ret;
}

int
ofs_addif(const char *dp, const char *device)
{
	return dpctl("add-if %s %s", dp, device);
}

static inline void
ofs_create_dp(struct tr069_instance_node *node)
{
	struct tr069_value_table *ift = DM_TABLE(node->table);

	const char *device;
	tr069_selector *devref;
	char listen[255];

	const char *argv[] = {
		OVS_OPENFLOWD,
		"--unixctl=none",
		"--listen", listen,
		"--fail=secure",
		"--out-of-band",
		NULL /* device */, "tcp:127.0.0.1",
#ifdef SDEBUG
		"--verbose",
#endif
		NULL
	};

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i}.Name */
	device = tr069_get_string_by_id(ift, cwmp__IGD_IfMap_OFSwitch_i_Name);
	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i}.DeviceReference */
	devref = tr069_get_selector_by_id(ift, cwmp__IGD_IfMap_OFSwitch_i_DeviceReference);

	if (!device || !*device || !devref) {
		EXIT();
		return;
	}

	_if_add2ifmap(device, *devref);

	dpctl("add-dp %s", device);
	if_linkup(device);

	snprintf(listen, sizeof(listen),
		 "punix:/var/run/openvswitch-%s.mgmt", device);
	argv[6] = device;

	supervise(argv);

	EXIT();
	return;
}

void
ofs_init(struct tr069_value_table *ift)
{
	insmod("openvswitch_mod");

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch */
	dp_map = tr069_get_instance_ref_by_id(ift, cwmp__IGD_IfMap_OFSwitch);
	if (dp_map) {
		pthread_rwlock_rdlock(&tr069_rwlock);

		for (struct tr069_instance_node *node = tr069_instance_first(dp_map);
		     node != NULL;
		     node = tr069_instance_next(dp_map, node))
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i} */
			ofs_create_dp(node);

		pthread_rwlock_unlock(&tr069_rwlock);
	}
}

/**
 * Set MACs of all datapath local ports to the datapath's first physical port
 * MAC.
 */
static inline void
ofs_set_macs(void)
{
	struct tr069_instance *if_inst;

	ENTER();

	if (!dp_map) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface */
	if_inst = tr069_get_instance_ref_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPOSS_InterfaceMap,
		cwmp__IGD_IfMap_Interface, 0
	});
	if (!if_inst) {
		EXIT();
		return;
	}

	for (struct tr069_instance_node *dp_node = tr069_instance_first(dp_map);
	     dp_node != NULL;
	     dp_node = tr069_instance_next(dp_map, dp_node)) {
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i} */
		const char *dp_name;
		tr069_selector *dp_devref;
		size_t dp_devref_len;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i}.Name */
		dp_name = tr069_get_string_by_id(DM_TABLE(dp_node->table), cwmp__IGD_IfMap_OFSwitch_i_Name);
		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.OFSwitch.{i}.DeviceReference */
		dp_devref = tr069_get_selector_by_id(DM_TABLE(dp_node->table), cwmp__IGD_IfMap_OFSwitch_i_DeviceReference);

		if (!dp_name || !*dp_name || !dp_devref)
			continue;
		dp_devref_len = tr069_sellen(*dp_devref);

		for (struct tr069_instance_node *if_node = tr069_instance_first(if_inst);
		     if_node != NULL;
		     if_node = tr069_instance_next(if_inst, if_node)) {
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i} */
			struct tr069_instance *dev_inst;
			const char *dev_name;

			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Name */
			dev_name = tr069_get_string_by_id(DM_TABLE(if_node->table), cwmp__IGD_IfMap_If_i_Name);
			/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device */
			dev_inst = tr069_get_instance_ref_by_id(DM_TABLE(if_node->table), cwmp__IGD_IfMap_If_i_Device);

			if (!dev_name || !*dev_name || !dev_inst)
				continue;

			for (struct tr069_instance_node *dev_node = tr069_instance_first(dev_inst);
			     dev_node != NULL;
			     dev_node = tr069_instance_next(dev_inst, dev_node)) {
				/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i} */
				tr069_selector *dev_devref;
				char dev_mac[20];

				/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
				dev_devref = tr069_get_selector_by_id(DM_TABLE(dev_node->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
				if (!dev_devref)
					continue;

				if (!(tr069_selcmp(*dev_devref, *dp_devref, dp_devref_len)) &&
				    getifmac(dev_name, dev_mac)) {
					/* interface is (first) switch port */
					vasystem("ifconfig %s hw ether %s", dp_name, dev_mac);
					update_LANdeviceMAC(dp_name, *dp_devref);
					EXIT();
					return;
				}
			}
		}
	}

	EXIT();
}

#define INET_ERLADDRSTRLEN (INET_ADDRSTRLEN + 2)

static inline void
inet_ntoerl(char *buffer, size_t size, struct in_addr addr)
{
	snprintf(buffer, size, "{%u,%u,%u,%u}",
		 ((uint8_t *)&addr.s_addr)[0],
		 ((uint8_t *)&addr.s_addr)[1],
		 ((uint8_t *)&addr.s_addr)[2],
		 ((uint8_t *)&addr.s_addr)[3]);
}

static const char **
update_flsc_argv(void)
{
	struct in_addr addr;
	static char dist_ip[INET_ERLADDRSTRLEN];
	static char remote_host[INET_ERLADDRSTRLEN];
	struct tr069_value_table *inf;

	static const char *argv[] = {
		ERL_BIN, "-noinput", "-mode", "embedded",

		/* distribution config */
		"-kernel", "inet_dist_use_interface", dist_ip,
		"-hidden",
		"-sname", "flsc",
		"-setcookie", NULL /* modified */,

		/* initial sasl_syslog config */
		"-sasl_syslog", "enabled", NULL /* modified */,
		"-sasl_syslog", "remote_host", remote_host,
		"-sasl_syslog", "multiline", NULL /* modified */,
		"-sasl_syslog", "rfc5424_bom", NULL /* modified */,
		"-sasl_syslog", "formatter", NULL /* modified */,

		"-boot", "/usr/lib/erlang/lib/flsc-" FLSC_VERSION "/ebin/flsc",
		NULL
	};

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Flow.Distribution.BindIPAddress */
	addr = tr069_get_ipv4_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Flow,
		cwmp__IGD_SCG_Flow_Distribution,
		cwmp__IGD_SCG_Flow_Dist_BindIPAddress, 0
	});
	inet_ntoerl(dist_ip, sizeof(dist_ip), addr);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Flow.Distribution.Cookie */
	argv[11] = tr069_get_string_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Flow,
		cwmp__IGD_SCG_Flow_Distribution,
		cwmp__IGD_SCG_Flow_Dist_Cookie, 0
	}) ? : "";

	/** VAR: InternetGatewayDevice.DeviceInfo */
	inf = tr069_get_table_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_DeviceInfo, 0
	});
	if (inf == NULL)
		return NULL;

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_GELFServer */
	addr = tr069_get_ipv4_by_id(inf, cwmp__IGD_DevInf_X_TPLINO_GELFServer);
	if (addr.s_addr != INADDR_ANY) {
		argv[26] = "sasl_syslog_gelf";
	} else {
		argv[26] = "sasl_syslog_rfc5424";

		/** VAR: InternetGatewayDevice.DeviceInfo.SyslogServer */
		addr = tr069_get_ipv4_by_id(inf, cwmp__IGD_DevInf_SyslogServer);
	}
	argv[14] = addr.s_addr != INADDR_ANY ? "true" : "false";
	inet_ntoerl(remote_host, sizeof(remote_host), addr);

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_MultilineSyslogEnabled */
	argv[20] = tr069_get_bool_by_id(inf, cwmp__IGD_DevInf_X_TPLINO_MultilineSyslogEnabled)
			? "true"
			: "false";

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_SyslogBOMEnabled */
	argv[23] = tr069_get_bool_by_id(inf, cwmp__IGD_DevInf_X_TPLINO_SyslogBOMEnabled)
			? "true"
			: "false";

	return argv;
}

static enum process_action
flsc_reaped_cb(struct process_info_t *p, enum process_state state,
	       int status __attribute__((unused)),
	       void *ud __attribute__((unused)))
{
	switch (state) {
	case PROCESS_RUNNING:
		/* undesired crash, keep (initial) syslogging synchronized */
		change_process_argv(p, update_flsc_argv());
		return PROCESS_RESTART;
	case PROCESS_DYING:
		/* desired termination */
		return PROCESS_REMOVE;
	default:
		break;
	}

	/* shouldn't be reached */
	return PROCESS_NOTHING;
}

void
start_flsc(void)
{
	struct tr069_instance *zones;

	ofs_set_macs();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
	zones = tr069_get_instance_ref_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Zone, 0
	});
	if (!zones)
		return;

	for (struct tr069_instance_node *node = tr069_instance_first(zones);
	     node != NULL;
	     node = tr069_instance_next(zones, node)) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
		if (tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Enabled)) {
			flsc_id = supervise_cb(update_flsc_argv(), 5, 20.,
					       flsc_reaped_cb, NULL);
			return;
		}
	}
}

void
config_epmd(void)
{
	struct in_addr addr;
	static char bind_ip[INET_ADDRSTRLEN];

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Flow.Distribution.BindIPAddress */
	addr = tr069_get_ipv4_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Flow,
		cwmp__IGD_SCG_Flow_Distribution,
		cwmp__IGD_SCG_Flow_Dist_BindIPAddress, 0
	});

	if (addr.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &addr, bind_ip, sizeof(bind_ip));
		setenv("ERL_EPMD_ADDRESS", bind_ip, 1);
	}
}

