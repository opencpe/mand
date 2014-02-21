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

#include "tr069.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_action.h"

#include "process.h"
#include "snmpd.h"

#define SDEBUG
#include "debug.h"

#define PURESNMPD       "/usr/sbin/puresnmpd"
#define PURESNMPD_CONF  "/tmp/etc/puresnmpd.conf"

void start_snmpd(void)
{
	FILE *fout;
	struct tr069_value_table *snmp;

	ENTER();
	snmp = tr069_get_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							    cwmp__IGD_X_TPLINO_NET_SNMP, 0});
	if (!snmp) {
		EXIT();
		return;
	}

	if (!tr069_get_bool_by_id(snmp, cwmp__IGD_SNMP_Enabled)) {
		EXIT();
		return;
	}

	fout = fopen(PURESNMPD_CONF, "w");
	if (!fout) {
		EXIT();
		return;
	}

	fprintf(fout,
		"logfile = /var/log/puresnmpd.log\n"
		"pidfile = /var/run/puresnmpd.pid\n"
		"listen = 0.0.0.0:161\n"
		"readcommunity = %s\n"
		"sysContact = %s\n"
		"sysLocation = %s\n",
		tr069_get_string_by_id(snmp, cwmp__IGD_SNMP_ReadCommunity),
		tr069_get_string_by_id(snmp, cwmp__IGD_SNMP_Contact),
		tr069_get_string_by_id(snmp, cwmp__IGD_SNMP_Location));
	fclose(fout);

	vsystem(PURESNMPD " -c " PURESNMPD_CONF);

	EXIT();
}

void stop_snmpd(void)
{
	killpidfile("/var/run/puresnmpd.pid");
}

void dm_restart_snmpd_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	stop_snmpd();
	start_snmpd();
}
