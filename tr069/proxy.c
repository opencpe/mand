/*
 * proxy management functions
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <ev.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#include "proxy.h"
#include "process.h"

#define SDEBUG
#include "debug.h"

#define PROXYD "/usr/bin/proxy"
#define PROXYCONF "/tmp/etc/proxy.conf"
#define HEARTBEAT_MS    60000

static int build_config(struct tr069_value_table *sct, FILE *fout);

static int scg_id = 0;

static ev_timer evstart;
static ev_tstamp last_beat;

static void scgtimer_cb(EV_P_ ev_timer *w, int revents __attribute__ ((unused)))
{
	if (last_beat + (HEARTBEAT_MS * 3) / 1000.0 < ev_now(EV_A)) {
		debug("(): heartbeat missed: %f .. %f\n", last_beat, ev_now(EV_A));
	}

	ev_timer_again (EV_A_ w);
}

static char **update_proxy_argv(void)
{
	struct in_addr addr;
	static char ipaddr[INET_ADDRSTRLEN];

	static char *argv[] = {
		PROXYD,
		"-l", ipaddr,
		"-a", "logx",
		NULL, /* optional "-x" */
		NULL
	};

	/** VAR: InternetGatewayDevice.DeviceInfo.SyslogServer */
	addr = tr069_get_ipv4_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_DeviceInfo,
		cwmp__IGD_DevInf_SyslogServer, 0
	});
	inet_ntop(AF_INET, &addr, ipaddr, INET_ADDRSTRLEN);

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_LoggingEnabled */
	argv[5] = tr069_get_bool_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
        	cwmp__IGD_DeviceInfo,
		cwmp__IGD_DevInf_X_TPLINO_LoggingEnabled, 0
	}) ? "-x" : NULL;

	return argv;
}

static enum process_action proxy_reaped_cb(struct process_info_t *p,
					   enum process_state state,
					   int status __attribute__((unused)),
					   void *ud __attribute__((unused)))
{
	switch (state) {
	case PROCESS_RUNNING:
		/* undesired crash, keep debug logging synchronized */
		change_process_argv(p, update_proxy_argv());
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

void start_proxy(void)
{
	int run_scg = 0;
	struct tr069_value_table *sct;
	FILE *fout;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl */
	sct = tr069_get_table_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl, 0
	});
	if (!sct) {
		EXIT();
		return;
	}

	fout = fopen(PROXYCONF, "w");
	if (fout) {
		run_scg = build_config(sct, fout);
		fclose(fout);
	}

	if (!run_scg) {
		EXIT();
		return;
	}

	scg_id = supervise_cb(update_proxy_argv(),
			      PROCESS_DEFAULT_MAX_RESTARTS,
			      PROCESS_DEFAULT_RESTART_TIMESPAN,
			      proxy_reaped_cb, NULL);
	if (scg_id < 1) {
		EXIT();
		return;
	}

	/*
	 * start heartbeat
	 */
	ev_timer_init(&evstart, scgtimer_cb, 0., (HEARTBEAT_MS * 3) / 1000.0);
	ev_timer_again(EV_DEFAULT_ &evstart);

	EXIT();
}

void stop_proxy(void)
{
	if (ev_is_active(&evstart))
		ev_timer_stop(EV_DEFAULT_ &evstart);

	if (scg_id)
		kill_supervise(scg_id, SIGTERM);
}

/*
 * toggle log level
 */
void toggle_proxy(void)
{
	if (scg_id)
		signal_supervise(scg_id, SIGUSR2);
}

void reload_proxy(void)
{
	int run_scg = 0;
	struct tr069_value_table *sct;
	FILE *fout;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl */
	sct = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl, 0});

	if (!sct) {
		stop_proxy();
		EXIT();
		return;
	}

	fout = fopen(PROXYCONF, "w");
	if (fout) {
		run_scg = build_config(sct, fout);
		fclose(fout);
	}

	if (!run_scg) {
		stop_proxy();
		EXIT();
		return;
	}

	signal_supervise(scg_id, SIGUSR1);
	EXIT();
}

void heartbeat_proxy(void)
{
	last_beat = ev_now(EV_DEFAULT_UC);
	ev_timer_again(EV_DEFAULT_UC_ &evstart);
}

static char *policymap[] = {
	"Ignore",
	"Accept",
	"Deny",
	"Redirect",
	"Proxy",
};

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}

static int get_ac_id(const tr069_selector sel)
{
	struct tr069_instance_node *ac;

	ac = tr069_get_instance_node_by_selector(sel);
	if (!ac)
		return 0;

	return ac->idm;
}

static int get_acl_id(const tr069_selector sel)
{
	struct tr069_instance_node *acl;

	acl = tr069_get_instance_node_by_selector(sel);
	if (!acl)
		return 0;

	return acl->idm;
}

static int build_config(struct tr069_value_table *sct, FILE *fout)
{
	int run_scg = 0;
	struct tr069_instance *acls;
	struct tr069_instance_node *acl;
	struct tr069_instance *zone;
	struct tr069_instance_node *zn;

	ENTER();

	acls = tr069_get_instance_ref_by_id(sct, cwmp__IGD_SCG_AccessControllList);
	if (!acls) {
		EXIT();
		return run_scg;
	}

	for (acl = tr069_instance_first(acls);
	     acl != NULL;
	     acl = tr069_instance_next(acls, acl)) {
		struct tr069_value_table *urit;
		struct tr069_instance *uris;
		struct tr069_instance_node *uri;
		unsigned int pol;
		const char *s;

		s = tr069_get_string_by_id(DM_TABLE(acl->table), cwmp__IGD_SCG_ACL_i_ACLId);
		fprintf(fout, ":%s %d %d %s\n", "ACL", acl->instance, acl->idm, s ? s : "-");

		pol = tr069_get_enum_by_id(DM_TABLE(acl->table), cwmp__IGD_SCG_ACL_i_DefaultPolicy);
		if (pol < sizeof(policymap) / sizeof(void *))
			fprintf(fout, "-%c %s\n", 'D', policymap[pol]);

		pol = tr069_get_enum_by_id(DM_TABLE(acl->table), cwmp__IGD_SCG_ACL_i_Policy);
		if (pol < sizeof(policymap) / sizeof(void *))
			fprintf(fout, "-%c %s\n", 'P', policymap[pol]);

		s = tr069_get_string_by_id(DM_TABLE(acl->table), cwmp__IGD_SCG_ACL_i_RedirectURL);
		if (s)
			fprintf(fout, "-%c %s\n", 'R', s);

		urit = tr069_get_table_by_id(DM_TABLE(acl->table), cwmp__IGD_SCG_ACL_i_URIs);
		if (!urit)
			continue;
		uris = tr069_get_instance_ref_by_id(urit, cwmp__IGD_SCG_ACL_i_URIs_URI);
		if (!uris)
			continue;

		for (uri = tr069_instance_first(uris);
		     uri != NULL;
		     uri = tr069_instance_next(uris, uri)) {
			s = tr069_get_string_by_id(DM_TABLE(uri->table), cwmp__IGD_SCG_ACL_i_URIs_URI_j_URI);
			if (s)
				fprintf(fout, "-%c %s\n", 'U', s);
		}
	}

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone */
	zone = tr069_get_instance_ref_by_id(sct, cwmp__IGD_SCG_Zone);
	if (!zone) {
		EXIT();
		return run_scg;
	}

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	for (zn = tr069_instance_first(zone);
	     zn != NULL;
	     zn = tr069_instance_next(zone, zn))
	{
		struct tr069_value_table *znt = DM_TABLE(zn->table);
		struct tr069_value_table *acst;
		struct tr069_value_table *portal;
		struct tr069_instance *acs;
		struct tr069_instance_node *ac;
		tr069_selector *sel;
		const char *s;

		/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
		if (!tr069_get_bool_by_id(znt, cwmp__IGD_SCG_Zone_i_Enabled))
			continue;

		run_scg |= 1;

		/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i}.ZoneId */
		s = tr069_get_string_by_id(znt, cwmp__IGD_SCG_Zone_i_ZoneId);
		fprintf(fout, ":%s %d %d %s\n", "Zone", zn->instance, zn->idm, s ? s : "-");

		s = tr069_get_string_by_id(znt, cwmp__IGD_SCG_Zone_i_WISPrSmartClientNextURL);
		if (s)
			fprintf(fout, "-%c %s\n", 'N', s);

		portal = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Portal);
		if (portal) {
			char buf[INET_ADDRSTRLEN];
			const char *ip = NULL;

			ip = ip2str(tr069_get_ipv4_by_id(portal, cwmp__IGD_SCG_Zone_i_Portal_Prefix), buf);
			if (ip)
				fprintf(fout, "-%c %s/%d\n", 'P', ip, tr069_get_uint_by_id(portal, cwmp__IGD_SCG_Zone_i_Portal_PrefixLen));
		}

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.KnownAccessClass */
		sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_KnownAccessClass);
		if (sel)
			fprintf(fout, "-%c %d %d\n", 'K', (*sel)[6], get_ac_id(*sel));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.OnlineAccessClass */
		sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_OnlineAccessClass);
		if (sel)
			fprintf(fout, "-%c %d %d\n", 'O', (*sel)[6], get_ac_id(*sel));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.UnknownAccessClass */
		sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_UnknownAccessClass);
		if (sel)
			fprintf(fout, "-%c %d %d\n", 'U', (*sel)[6], get_ac_id(*sel));

		acst = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_AccessClasses);
		acs = tr069_get_instance_ref_by_id(acst, cwmp__IGD_SCG_Zone_i_ACs_AccessClass);
		if (!acs)
			continue;

		for (ac = tr069_instance_first(acs);
		     ac != NULL;
		     ac = tr069_instance_next(acs, ac))
		{
			s = tr069_get_string_by_id(DM_TABLE(ac->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId);
			fprintf(fout, ":%s %d %d %s\n", "AccessClass", ac->instance, ac->idm, s ? s : "-");

			acls = tr069_get_instance_ref_by_id(DM_TABLE(ac->table), cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessControllLists);
			if (!acls)
				continue;
			for (acl = tr069_instance_first(acls);
			     acl != NULL;
			     acl = tr069_instance_next(acls, acl))
			{
				tr069_selector *ldev;

				ldev = tr069_get_selector_by_id(DM_TABLE(acl->table),
								cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessControllLists_k_AccessControllList);
				if (!ldev)
					continue;
				fprintf(fout, "-%c %d %d\n", 'A', (*ldev)[3], get_acl_id(*ldev));
			}
		}
	}

	EXIT();
	return run_scg;
}
