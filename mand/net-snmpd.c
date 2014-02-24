/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 Travelping GmbH
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_action.h"

#include "process.h"
#include "snmpd.h"

#define SDEBUG
#include "debug.h"

#define NET_SNMPD       "/usr/sbin/snmpd"
#define NET_SNMPD_PATH  "/tmp/etc/snmp"
#define NET_SNMPD_CONF  NET_SNMPD_PATH "/snmpd.conf"
#define NET_SNMPD_PID   "/var/run/snmpd.pid"
#define AGENTX_PATH     "/var/agentx"
#define AGENTX_MASTER   AGENTX_PATH "/master"

static int snmp_running = 0;

#if defined(HAVE_NET_SNMP)

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "snmp/radiusAuthServ.h"
#include "snmp/radiusAccServ.h"
#include "snmp/radiusAuthClient.h"
#include "snmp/radiusAccClient.h"
#include "snmp/radiusAuthServerExtTable.h"
#include "snmp/radiusAccServerExtTable.h"
#include "snmp/radiusAuthClientExtTable.h"
#include "snmp/radiusAccClientExtTable.h"
#include "snmp/zoneAccessClassTable.h"

static int keep_running;
static pthread_t tid;

static int check_and_process(void)
{
        int             numfds;
        fd_set          fdset;
        struct timeval  timeout = { LONG_MAX, 0 };
	struct timeval *tvp = &timeout;
        int             count;
        int             fakeblock = 0;

        numfds = 0;
        FD_ZERO(&fdset);
        snmp_select_info(&numfds, &fdset, tvp, &fakeblock);

        if (fakeblock != 0)
                tvp = NULL;

	/* select may block, so make this a cancelation point */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        count = select(numfds, &fdset, 0, 0, tvp);
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	return agent_check_and_process(0);
}

void agentx_shutdown(void *parm __attribute__((unused)))
{
	ENTER();
	debug(": AgentX Thread shutdown");

	snmp_shutdown("DM");
	SOCK_CLEANUP;

	EXIT();
}

static void *agentx_thread(void *arg __attribute__ ((unused)))
{
	ENTER();

	/* wait for max 5 seconds for the master socket to arrive */
	for (int i = 0; i < 50; i++) {
		if (access(AGENTX_MASTER, R_OK) != 0)
			usleep(100 * 1000); /* sleep 100ms */
	}
	if (access(AGENTX_MASTER, R_OK) != 0) {
		EXIT();
		return NULL;
	}

	/* disable cancelability, defered */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

	/* nobody can cancel us now, unless we want them to.... */
	pthread_cleanup_push(agentx_shutdown, NULL);

	snmp_enable_calllog();
	snmp_enable_syslog();
	//snmp_enable_stderrlog();
	snmp_set_do_debugging(1);

	debug("AgentX Thread started");

	netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);

	SOCK_STARTUP;

	init_agent("DM");

	init_radiusAuthServ();
	init_radiusAccServ();
	init_radiusAuthClient();
	init_radiusAccClient();
	init_radiusAuthServerExtTable();
	init_radiusAccServerExtTable();
	init_radiusAuthClientExtTable();
	init_radiusAccClientExtTable();
	init_zoneAccessClassTable();

	init_snmp("DM");
	snmp_log(LOG_INFO, "DM is up and running.\n");

	while(keep_running)
		check_and_process();
	debug(": stopping AgentX Thread");

	pthread_cleanup_pop(1);

	EXIT();
	return NULL;
}

static void start_agentx(void)
{
	keep_running = 1;
	pthread_create(&tid, NULL, agentx_thread, NULL);
}

static void stop_agentx(void)
{
	if (keep_running) {
		keep_running = 0;
		pthread_cancel(tid);
		pthread_join(tid, NULL);
	}
}

#else

static void start_agentx(void)
{
}

static void stop_agentx(void)
{
}

#endif

static void build_config(struct dm_value_table *snmp)
{
	FILE *fout;

	mkdir(NET_SNMPD_PATH, 0755);

	fout = fopen(NET_SNMPD_CONF, "w");
	if (!fout) {
		EXIT();
		return;
	}

	fprintf(fout,
		"master agentx\n"
		"com2sec TPLINO default \"%s\"\n"
		"group tplino_ro v1 TPLINO\n"
		"group tplino_ro v2c TPLINO\n"
		"group tplino_ro usm TPLINO\n"
		"view all included  .1 80\n"
		"access tplino_ro \"\" any noauth exact all none none\n"
		"sysContact %s\n"
		"sysLocation %s\n",
		dm_get_string_by_id(snmp, cwmp__IGD_SNMP_ReadCommunity),
		dm_get_string_by_id(snmp, cwmp__IGD_SNMP_Contact),
		dm_get_string_by_id(snmp, cwmp__IGD_SNMP_Location));

	fclose(fout);

	mkdir(AGENTX_PATH, 0755);
}

void start_snmpd(void)
{
	struct dm_value_table *snmp;

	ENTER();
	snmp = dm_get_table_by_selector((dm_selector){cwmp__InternetGatewayDevice,
							    cwmp__IGD_X_TPLINO_NET_SNMP, 0});
	if (!snmp) {
		EXIT();
		return;
	}

	if (!dm_get_bool_by_id(snmp, cwmp__IGD_SNMP_Enabled)) {
		EXIT();
		return;
	}

	build_config(snmp);

	unlink(AGENTX_MASTER);
	vsystem(NET_SNMPD " -p " NET_SNMPD_PID);
	start_agentx();
	snmp_running = 1;

	EXIT();
}

void stop_snmpd(void)
{
	stop_agentx();
	killpidfile(NET_SNMPD_PID);
	snmp_running = 0;
}

void dm_restart_snmpd_action(const dm_selector sel __attribute__((unused)),
			     enum dm_action_type type __attribute__((unused)))
{
	struct dm_value_table *snmp;

	ENTER();

	snmp = dm_get_table_by_selector((dm_selector){cwmp__InternetGatewayDevice,
							    cwmp__IGD_X_TPLINO_NET_SNMP, 0});
	if (!snmp) {
		EXIT();
		return;
	}

	if (!dm_get_bool_by_id(snmp, cwmp__IGD_SNMP_Enabled)) {
		if (snmp_running)
			stop_snmpd();
		EXIT();
		return;
	}

	if (!snmp_running) {
		start_snmpd();
	} else {
		build_config(snmp);
		signalpidfile(NET_SNMPD_PID, SIGHUP);
	}
	EXIT();
}


