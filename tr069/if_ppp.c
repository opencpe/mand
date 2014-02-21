#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <signal.h>

#include <net/if.h>

#define SDEBUG 1
#include "debug.h"
#include "list.h"

#include "tr069_token.h"
#include "tr069_store.h"

#include "ifup.h"
#include "inet_helper.h"

#define PPPD "/usr/sbin/pppd"
#define PPP_CONF "/var/etc/ppp.options"

void ppp_defaults(FILE *fout, struct tr069_value_table *ift)
{
	int do_idle = 1;

	ENTER();

	fprintf(fout, "nodetach\n");
	fprintf(fout, "defaultroute\n");

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.DNSOverrideAllowed */
	if (tr069_get_bool_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_DNSOverrideAllowed))
		fprintf(fout, "usepeerdns\n");

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.ConnectionTrigger */
	switch(tr069_get_enum_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_ConnectionTrigger)) {
		case 0:                            // OnDemand
			fprintf(fout, "demand\n");
			break;
		case 1:                            // AlwaysOn
			fprintf(fout, "persist\n");
			do_idle = 0;
			break;
		case 2:                            // Manual
			break;
	}

	if (do_idle) {
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.IdleDisconnectTime */
		fprintf(fout, "idle %d\n",
			tr069_get_int_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_IdleDisconnectTime));
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.PPPLCPEcho */
	fprintf(fout, "lcp-echo-interval %d\n",
		tr069_get_uint_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_PPPLCPEcho));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.PPPLCPEchoRetry */
	fprintf(fout, "lcp-echo-failure %d\n",
		tr069_get_int_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_PPPLCPEchoRetry));

#if 0
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.AutoDisconnectTime */
	i = tr069_get_uint_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_AutoDisconnectTime);
#endif

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Username */
	fprintf(fout, "user \"%s\"\n",
		tr069_get_string_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Username));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Password */
	fprintf(fout, "password \"%s\"\n",
		tr069_get_string_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Password));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.MaxMRUSize */
	fprintf(fout, "mtu %d\n",
		tr069_get_uint_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_MaxMRUSize));
	fprintf(fout, "mru %d\n",
		tr069_get_uint_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_MaxMRUSize));

	EXIT();
}

struct ppp_info_t {
        struct ppp_info_t   *next;
        int                 id;
	tr069_selector      sel;
};

static struct {
        struct process_info_t   *next;
	int                     id;
        pthread_mutex_t         mutex;
} ppp_info_head = {
	.next		= NULL,
	.id             = 0,
	.mutex		= PTHREAD_MUTEX_INITIALIZER,
};

static inline int ppp_sel_cmp(struct ppp_info_t *node, const tr069_selector sel)
{
        return tr069_selcmp(node->sel, sel, TR069_SELECTOR_LEN);
}

int ppp_stopif(const char *device __attribute__ ((unused)), const tr069_selector sel)
{
	int id = 0;
	struct ppp_info_t *p;

        ENTER();
        pthread_mutex_lock(&ppp_info_head.mutex);
        list_search(struct ppp_info_t, ppp_info_head, sel, ppp_sel_cmp, p);
        if (p) {
		id = p->id;
		list_remove(struct ppp_info_t, ppp_info_head, p);
		free(p);
	}
        pthread_mutex_unlock(&ppp_info_head.mutex);
	if (id)
		kill_supervise(id, SIGTERM);

        EXIT();
	return 0;
}

int ppp_stop_condev(const char *device __attribute__ ((unused)), const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct ppp_info_t *p, *n;

	ENTER();

	debug("(): iface: %s\n", sel2str(b1, sel));

	pthread_mutex_lock(&ppp_info_head.mutex);
	list_foreach_safe(struct ppp_info_t, ppp_info_head, p, n) {
		if (tr069_selcmp(p->sel, sel, 5) == 0) {
			kill_supervise(p->id, SIGTERM);
			list_remove(struct ppp_info_t, ppp_info_head, p);
			free(p);
		}
	}
	pthread_mutex_unlock(&ppp_info_head.mutex);

	EXIT();
	return 0;
}

void ppp_stop_all()
{
	struct ppp_info_t *p, *n;

	ENTER();

	pthread_mutex_lock(&ppp_info_head.mutex);
	list_foreach_safe(struct ppp_info_t, ppp_info_head, p, n) {
		kill_supervise(p->id, SIGTERM);
		list_remove(struct ppp_info_t, ppp_info_head, p);
		free(p);
	}
	pthread_mutex_unlock(&ppp_info_head.mutex);

	EXIT();
}

int pppoe_ifup(const char *device, tr069_id wandev, struct tr069_instance_node *ift_node, struct tr069_instance_node *pppc_node)
{
	struct tr069_value_table *pppc = DM_TABLE(pppc_node->table);

	/* write ppp config file .... */
	FILE *fout;

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Enabled */
	if (!tr069_get_bool_by_id(pppc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Enable)) {
		EXIT();
		return 0;
	}

	if (!(fout = fopen(PPP_CONF, "w"))) {
		fprintf(stderr, "failed to open %s for writing\n", PPP_CONF);
		EXIT();
		return -1;
	}

	fprintf(fout, "ipparam wan.%d.%d.%d\n", wandev, ift_node->instance, pppc_node->instance);

	fprintf(fout, "plugin rp-pppoe.so\n");
	fprintf(fout, "connect /bin/true\n");
	fprintf(fout, "nic-%s\n", device);

	ppp_defaults(fout, pppc);
	fclose(fout);

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i} */
	ppp_startif(device,
		    PPP_CONF,
		    (tr069_selector){cwmp__InternetGatewayDevice,
				    cwmp__IGD_WANDevice,
				    wandev,
				    cwmp__IGD_WANDev_i_WANConnectionDevice,
				    ift_node->instance,
				    cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
				    pppc_node->instance, 0});

	EXIT();
	return 0;
}

int ppp_startif(const char *device __attribute__ ((unused)), const char *conff, const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	int id;

	ENTER();

	debug("(): iface: %s\n", sel2str(b1, sel));

	insmod("slhc");
	insmod("ppp_generic");
	insmod("pppox");
	insmod("pppoe");

	char *argv[] = {PPPD, "file", conff, NULL};
	id = supervise(argv);
	if (id) {
		struct ppp_info_t *p;

		p = malloc(sizeof( struct ppp_info_t ));
		if (!p) {
			EXIT();
			return 0;
		}
		p->id = id;
		tr069_selcpy(p->sel, sel);

		pthread_mutex_lock(&ppp_info_head.mutex);
		list_append(struct ppp_info_t, ppp_info_head, p);
		pthread_mutex_unlock(&ppp_info_head.mutex);
	}

	EXIT();
	return 0;
}

/*
 * called from ppp hotplug
 */
int ppp_ipup(const char *device, const tr069_selector sel)
{
	struct tr069_value_table *ift;

	ENTER();

	if_add2ifmap(device, sel);
	wan_sched_init(device, sel);

	ift = tr069_get_table_by_selector(sel);
	if (ift) {
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.ExternalIPAddress */
		tr069_set_ipv4_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_ExternalIPAddress, getifip(device));
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.RemoteIPAddress */
		tr069_set_ipv4_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_RemoteIPAddress, getifdstip(device));
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Uptime */
		tr069_set_uint_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Uptime, monotonic_time());
	}

	EXIT();
	return 1;
}

int ppp_ipdown(const char *device __attribute__ ((unused)), const tr069_selector sel)
{
	struct tr069_value_table *ift;

	ENTER();

	ift = tr069_get_table_by_selector(sel);
	if (ift) {
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.ExternalIPAddress */
		tr069_set_ipv4_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_ExternalIPAddress, (struct in_addr){ .s_addr = INADDR_NONE });
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.RemoteIPAddress */
		tr069_set_ipv4_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_RemoteIPAddress, (struct in_addr){ .s_addr = INADDR_NONE });
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Uptime */
		tr069_set_uint_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Uptime, 0);
	}

	EXIT();

	return 1;
}
