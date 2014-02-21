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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_notify.h"
#include "tr069_action.h"

#define SDEBUG
#include "debug.h"

#include "monitor.h"
#include "process.h"
#include "utils/logx.h"

static int set_monitor_client(struct tr069_value_table *clnt, const tr069_selector monitor, int type)
{
	struct tr069_instance *mon;
	struct tr069_instance_node *n;

	unsigned int monid;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorId */
	monid = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorId);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor */
	mon = tr069_get_instance_ref_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Monitor, 0
	});

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Client */
	n = find_instance(mon, cwmp__IGD_SCG_Mon_i_Client,
			  T_SELECTOR, &init_DM_SELECTOR(&clnt->id, 0));
	if (!n) {
		tr069_selector sb = { cwmp__InternetGatewayDevice,
				      cwmp__IGD_X_TPLINO_NET_SessionControl,
				      cwmp__IGD_SCG_Monitor, 0};
		tr069_id id = TR069_ID_AUTO_OBJECT;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor */
		n = tr069_add_instance_by_selector(sb, &id);
		if (!n) {
			EXIT();
			return 0;
		}
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.MonitorId */
	tr069_set_uint_by_id(DM_TABLE(n->table), cwmp__IGD_SCG_Mon_i_MonitorId, monid);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Type */
	tr069_set_enum_by_id(DM_TABLE(n->table), cwmp__IGD_SCG_Mon_i_Type, type);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Client */
	tr069_set_selector_by_id(DM_TABLE(n->table), cwmp__IGD_SCG_Mon_i_Client, clnt->id);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Target */
	tr069_set_selector_by_id(DM_TABLE(n->table), cwmp__IGD_SCG_Mon_i_Target, monitor);

	update_instance_node_index(n);

	EXIT();
	return 1;
}

static int del_monitor_client(struct tr069_value_table *clnt)
{
	struct tr069_instance *mon;
	struct tr069_instance_node *n;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor */
	mon = tr069_get_instance_ref_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Monitor, 0
	});

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Client */
	n = find_instance(mon, cwmp__IGD_SCG_Mon_i_Client,
			  T_SELECTOR, &init_DM_SELECTOR(&clnt->id, 0));

	if (n) {
#if defined(SDEBUG)
		char b1[128];
#endif
		debug(": removing monitor:  %p (%s)", DM_TABLE(n->table), sel2str(b1, DM_TABLE(n->table)->id));

		tr069_del_table_by_selector(DM_TABLE(n->table)->id);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorId */
		tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorId, 0);
	}

	return 1;
}

void client_set_monitor_id(struct tr069_value_table *clnt, const char *mid, int type)
{
	tr069_selector monitor = {0};

	ENTER(": monitor: \"%s\", type: %d", mid ? : "", type);

	if (mid && *mid) {
		struct tr069_instance *mts;
		struct tr069_instance_node *mt;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.MonitoringTarget */
		mts = tr069_get_instance_ref_by_selector((tr069_selector) {
			cwmp__InternetGatewayDevice,
			cwmp__IGD_X_TPLINO_NET_SessionControl,
			cwmp__IGD_SCG_MonitoringTarget, 0
		});
		if (!mts) {
			EXIT();
			return;
		}

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.MonitoringTarget.{i} */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.MonitoringTarget.{i}.MonitoringTargetId */
		mt = find_instance(mts, cwmp__IGD_SCG_MonTarget_i_MonitoringTargetId, T_STR, &init_DM_STRING((char *)mid, 0));
		if (!mt) {
			EXIT();
			return;
		}

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.MonitoringTarget.{i}.Enabled */
		if (!tr069_get_bool_by_id(DM_TABLE(mt->table), cwmp__IGD_SCG_MonTarget_i_Enabled)) {
			EXIT();
			return;
		}

		tr069_selcpy(monitor, DM_TABLE(mt->table)->id);
	}

	/*
	 * explicitly do not execute MonitorTarget set-hook, since that would screw the Monitor Type,
	 * also note that there may be notifications on the MonitorTarget
	 */
	client_set_monitor_target(clnt, &monitor, type);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorTarget */
	tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorTarget, monitor);

	EXIT();
}

void client_set_monitor_target(struct tr069_value_table *clnt, tr069_selector *monitor, int type)
{
	if (monitor && (*monitor)[0])
		set_monitor_client(clnt, *monitor, type);
	else
		del_monitor_client(clnt);
}

int set_IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorTarget(struct tr069_value_table *base,
						  tr069_id id __attribute__ ((unused)),
						  const struct tr069_element *elem __attribute__ ((unused)),
						  DM_VALUE *st, DM_VALUE val)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	ENTER();
	tr069_selector *monitor = DM_SELECTOR(val);

	debug(": monitor:  %s", monitor ? sel2str(b1, *monitor) : "NULL");

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.MonitoringTarget.{i} */
	if (monitor && (*monitor)[0] != 0 &&
	    ((*monitor)[0] != cwmp__InternetGatewayDevice ||
	     (*monitor)[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	     (*monitor)[2] != cwmp__IGD_SCG_MonitoringTarget ||
	     (*monitor)[3] == 0 ||
	     (*monitor)[4] != 0)) {
		EXIT();
		return DM_INVALID_VALUE;
	}

	client_set_monitor_target(base, monitor, cwmp___IGD_SCG_Mon_i_Type_Manual);
	if (!monitor) {
		tr069_free_selector_value(st);
		EXIT();
		return DM_OK;
	}

	EXIT();
	return tr069_set_selector_value(st, *monitor);
}

/**
 * delete/stop all monitoring sessions on a monitoring target
 */
static void del_all_monitors(struct tr069_instance_node *node)
{
	struct tr069_value_table *tgt = DM_TABLE(node->table);
	struct tr069_instance *mon;
	struct tr069_instance_node *n;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor */
	mon = tr069_get_instance_ref_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Monitor, 0
	});

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i} */
	n = tr069_instance_first(mon);
	while (n) {
		struct tr069_instance_node *next = tr069_instance_next(mon, n);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Client */
		tr069_selector *clnt = tr069_get_selector_by_id(DM_TABLE(n->table), cwmp__IGD_SCG_Mon_i_Client);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Monitor.{i}.Target */
		tr069_selector *monitor = tr069_get_selector_by_id(DM_TABLE(n->table), cwmp__IGD_SCG_Mon_i_Target);

		if (clnt && monitor && !tr069_selcmp(*monitor, tgt->id, TR069_SELECTOR_LEN)) {
			struct tr069_instance_node *clntnode = tr069_get_instance_node_by_selector(*clnt);
#if defined(SDEBUG)
			char b1[128];
#endif
			debug(": removing monitor:  %p (%s)", DM_TABLE(n->table), sel2str(b1, DM_TABLE(n->table)->id));

			tr069_del_table_by_selector(DM_TABLE(n->table)->id);

			/*
			 * explicitly do not execute MonitorTarget set-hook since we can handle the
			 * Monitoring Session deletion more efficiently.
			 * also note that there may be notifications on the MonitorTarget
			 */
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorTarget */
			tr069_set_selector_by_id(DM_TABLE(clntnode->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorTarget,
						 (tr069_selector) {0});
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorId */
			tr069_set_uint_by_id(DM_TABLE(clntnode->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorId, 0);
		}

		n = next;
	}

	EXIT();
}

int set_IGD_SCG_MonTarget_i_Enabled(struct tr069_value_table *base,
				    tr069_id id __attribute__ ((unused)),
				    const struct tr069_element *elem __attribute__ ((unused)),
				    DM_VALUE *st, DM_VALUE val)
{
	struct tr069_instance_node *node = cast_table2node(base);

	set_DM_BOOL(*st, DM_BOOL(val));
	if (!DM_BOOL(val))
		/* Monitoring Target disabled */
		del_all_monitors(node);

	return 0;
}

void del_IGD_SCG_MonitoringTarget(const struct tr069_table *kw __attribute__ ((unused)),
				  tr069_id id __attribute__ ((unused)),
				  struct tr069_instance *inst __attribute__ ((unused)),
				  struct tr069_instance_node *node)
{
	del_all_monitors(node);
}

