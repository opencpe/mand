#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ev.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_action.h"
#include "tr069_strings.h"

#define SDEBUG
#include "dm_assert.h"
#include "debug.h"

#include "ifup.h"
#include "if_device.h"
#include "client.h"
#include "radlib.h"
#include "radius.h"
#include "firewall.h"
#include "session.h"
#include "monitor.h"
#include "ippool.h"

static int exit_client_accessclass(struct tr069_value_table *clnt, const char *username, int cause, ticks_t rt_now,
				   authentication_cb cb, void *user);
static int set_client_accessclass(struct tr069_value_table *client, const char *username, const tr069_selector ac,
				  int cause, const char *user_agent, ticks_t rt_now);
static void start_session(struct tr069_value_table *base, tr069_selector * const class, const char *sessionid);
static void stop_session(struct tr069_value_table *base, int cause, ticks_t now);

static int start_client_authentication(struct tr069_value_table *znt, struct tr069_value_table *clnt,
				       const char *sessionid, const char *username, const char *password, const char *tag, int cause,
				       const char *user_agent,
				       authentication_cb cb, void *user);
struct client_info {
	ev_timer timer;
};

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}

static char *get_session_id(char *id, size_t len)
{
	static uint64_t session_id = 0;

	if (session_id == 0)
		session_id = (uint64_t)havege_rand(&h_state) << (8 * (sizeof(uint64_t) - sizeof(int)));

	snprintf(id, len, "%016llX", session_id++);

	return id;
}

static const char *get_acct_session_id(struct tr069_value_table *clnt, char *id, size_t len)
{
	const char *sessionid;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AcctSessionId */
	sessionid = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId);
	if (!sessionid || !*sessionid) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
		sessionid = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId);
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId, sessionid);
	} else
		sessionid = get_session_id(id, len);

	return sessionid;
}

struct tr069_value_table *hs_get_zone_by_device(const tr069_selector sel)
{
	struct tr069_instance *zone;
	struct tr069_instance_node *zn;
	struct tr069_value_table *znt;
	tr069_selector f;

#if defined(SDEBUG)
       char b1[128];
#endif

	ENTER();

	debug("(): sel: %s\n", sel2str(b1, sel));

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_LANDevice ||
	    sel[2] == 0) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
	zone = tr069_get_instance_ref_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0});
	if (!zone) {
		EXIT();
		return NULL;
	}

	tr069_selcpy(f, sel);
	f[3] = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.LANDevice */
	zn = find_instance(zone, cwmp__IGD_SCG_Zone_i_LANDevice, T_SELECTOR, &init_DM_SELECTOR(&f, 0));
	znt = zn ? DM_TABLE(zn->table) : NULL;

	EXIT_MSG(" Zone: %p", znt);
	return znt;
}

struct tr069_value_table *hs_get_zone_by_zoneid(const char *name)
{
	struct tr069_instance *zone;
	struct tr069_instance_node *zn;
	struct tr069_value_table *znt;

	ENTER();

	debug("(): name: %s\n", name);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
	zone = tr069_get_instance_ref_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0});
	if (!zone) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.ZoneId */
	zn = find_instance(zone, cwmp__IGD_SCG_Zone_i_ZoneId, T_STR, &init_DM_STRING(name, 0));
	znt = zn ? DM_TABLE(zn->table) : NULL;

	EXIT_MSG(" Zone: %p", znt);
	return znt;
}

struct tr069_value_table *hs_get_zone_by_id(tr069_id id)
{
	struct tr069_value_table *znt = NULL;

	ENTER(": id: %d", id);

	if (id != 0) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
		znt = tr069_get_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
					cwmp__IGD_X_TPLINO_NET_SessionControl,
					cwmp__IGD_SCG_Zone,
					id, 0});
	}
	EXIT_MSG(": Zone: %p", znt);
	return znt;
}

static const char *get_actag_by_selector(const tr069_selector sel)
{
	struct tr069_value_table *act;

	act = tr069_get_table_by_selector(sel);
	if (!act)
		return NULL;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
	return tr069_get_string_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId);
}

static struct tr069_value_table *get_access_class(const tr069_selector class)
{
	struct tr069_value_table *act;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	if (!class ||
	    class[0] != cwmp__InternetGatewayDevice ||
	    class[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    class[2] != cwmp__IGD_SCG_Zone ||
	    class[3] == 0 ||
	    class[4] != cwmp__IGD_SCG_Zone_i_AccessClasses ||
	    class[5] != cwmp__IGD_SCG_Zone_i_ACs_AccessClass ||
	    class[6] == 0 ||
	    class[7] != 0) {
		EXIT();
		return NULL;
	}

	act = tr069_get_table_by_selector(class);

	EXIT_MSG(": act: %p", act);
	return act;
}

static void add_client_to_natpool(struct tr069_value_table *clnt, tr069_selector *natpool)
{
	struct tr069_instance_node *node = cast_table2node(clnt);
	struct tr069_value_table *natp;
	struct in_addr nataddr;
	unsigned int start_port = 0;
	unsigned int end_port = 0;
	int nat_ok = 0;

	ENTER();

	if (!natpool) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.i */
	if ((*natpool)[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    (*natpool)[2] != cwmp__IGD_SCG_NATPool ||
	    (*natpool)[3] == 0 ||
	    (*natpool)[4] != 0)
	{
		EXIT();
		return;
	}

	natp = tr069_get_table_by_selector(*natpool);
	if (!natp) {
		EXIT();
		return;
	}


	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RequestedNATIPAddress */
	nataddr = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATIPAddress);
	if (nataddr.s_addr != INADDR_NAS_SELECT) {
		if (tr069_get_enum_by_id(natp, cwmp__IGD_SCG_NP_i_Translation) == cwmp___IGD_SCG_NP_i_Translation_PortKeyed) {
			/* RADIUS selected IP is not (yet) supported on port keyed translations */
			nataddr.s_addr = INADDR_NAS_SELECT;
		}
		if (check_natpool_addr(natp, nataddr, 0)) {
			nat_ok = 1;
		} else
			/* invalid NATIP, fallback to pool select */
			nataddr.s_addr = INADDR_NAS_SELECT;
	}

	if (nataddr.s_addr == INADDR_NAS_SELECT) {
		struct in_addr addr;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
		addr = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
		nat_ok = alloc_natpool_addr(natp, addr, &nataddr, &start_port, &end_port);
	}

	if (nat_ok) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
		tr069_set_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress, nataddr);
		update_index(cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress, node);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
		tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart, start_port);
		update_index(cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart, node);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
		tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd, end_port);
		update_index(cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd, node);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i} */
		fw_natp_create(natp, clnt);
	}

	EXIT();
}

static void remove_client_from_natpool(struct tr069_value_table *clnt, tr069_selector *natpool)
{
	struct tr069_instance_node *node = cast_table2node(clnt);
	struct tr069_value_table *natp;
	struct in_addr nataddr;
	unsigned int start_port;

	ENTER();

	if (!natpool) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.LANDevice.i.LANEthernetInterfaceConfig */
	if ((*natpool)[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    (*natpool)[2] != cwmp__IGD_SCG_NATPool ||
	    (*natpool)[3] == 0 ||
	    (*natpool)[4] != 0)
	{
		EXIT();
		return;
	}

	natp = tr069_get_table_by_selector(*natpool);
	if (!natp) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i} */
	fw_natp_remove(natp, clnt);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	nataddr = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
	start_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart);
	release_natpool_addr(natp, nataddr, start_port);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	tr069_set_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress, (struct in_addr){ .s_addr = INADDR_NONE});
	update_index(cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress, node);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart, 0);
	update_index(cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart, node);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd, 0);
	update_index(cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd, node);
}

static void switch_natpool(struct tr069_value_table *clnt, tr069_selector *new)
{
	tr069_selector *old;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPool */
	old = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPool);
	if (tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATIPAddress).s_addr == INADDR_NAS_SELECT &&
	    old && new &&
	    tr069_selcmp(*old, *new, TR069_SELECTOR_LEN) == 0) {
		/* nothing to do */
		EXIT();
		return;
	}

	if (old)
		remove_client_from_natpool(clnt, old);
	if (new)
		add_client_to_natpool(clnt, new);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPool */
	tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPool, *new);

	EXIT();
}

static void remove_client(struct tr069_value_table *clnt)
{
#if defined(SDEBUG)
	char b1[128];
#endif

	debug(": removing client: %p (%s)", clnt, sel2str(b1, clnt->id));
	tr069_del_table_by_selector(clnt->id);
}

struct cta_info
{
	int reason;
	ticks_t stop_time;

	tr069_selector old_ac;
	ticks_t old_timeout;
	uint64_t old_maxInOctets;
	uint64_t old_maxOutOctets;
	uint64_t old_maxTotalOctets;
};

static void add_max_volume(struct tr069_value_table *clnt, tr069_id attr, uint64_t old_volume)
{
	uint64_t volume;

	volume = tr069_get_uint64_by_id(clnt, attr);
	if (volume > 0)
		tr069_set_uint64_by_id(clnt, attr, volume + old_volume);
}

/* set ValidTill to an absolute value */
static void set_valid_till(struct tr069_value_table *clnt, ticks_t vt_new)
{
	ticks_t vt_old;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
	vt_old = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ValidTill);
	if (vt_new == 0 || vt_new > vt_old)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
		tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ValidTill, vt_new);
}

static void inc_valid_till(struct tr069_value_table *clnt, ticks_t rt_now)
{
	unsigned int timeout;
	ticks_t vt_new = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.KeepAliveTimeout */
	timeout = time2ticks(tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_KeepAliveTimeout));
	if (timeout > 0)
		vt_new = rt_now + timeout;
	set_valid_till(clnt, vt_new);
}

static void cta_final_cb(int res,
			 struct tr069_value_table *clnt,
			 void *user)
{
	struct cta_info *cta = (struct cta_info *)user;
#if defined(SDEBUG)
	char b1[128];
	char b2[128];
#endif
	ENTER();

	debug(": Client: %p (%s), cta: %p, Res: %d\n", clnt, clnt ? sel2str(b1, clnt->id) : "NULL", cta, res);
	if (!clnt || !cta) {
		free(cta);
		EXIT();
		return;
	}

	if (res == AUTH_STATE_ACCEPTED) {
		tr069_selector *new_ac;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
		new_ac = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);

		debug(": old AC: %s, new AC: %s", sel2str(b1, cta->old_ac), new_ac ? sel2str(b2, *new_ac) : "NULL");

		if (new_ac && tr069_selcmp(*new_ac, cta->old_ac, TR069_SELECTOR_LEN) == 0) {
			/* extend current session */
			unsigned int timeout;

			timeout = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout);
			if (timeout > 0)
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout, timeout + cta->old_timeout);

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxInputOctets */
			add_max_volume(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxInputOctets, cta->old_maxInOctets);
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxOutputOctets */
			add_max_volume(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxOutputOctets, cta->old_maxOutOctets);
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxTotalOctets */
			add_max_volume(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxTotalOctets, cta->old_maxTotalOctets);
		}
		else
			set_client_accessclass(clnt, NULL, *new_ac, cta->reason, NULL, cta->stop_time);
	}
	else
		exit_client_accessclass(clnt, NULL, cta->reason, cta->stop_time, NULL, NULL);

	free(cta);

	EXIT();
}

static int client_termination_action(struct tr069_value_table *clnt, int reason, ticks_t stop_time)
{
	struct cta_info *cta;
	tr069_selector zone;
	struct tr069_value_table *znt;
	tr069_selector *old_ac;
	const char *old_tag;

	ENTER();

	radius_accounting_request(RAD_UPDATE, clnt, 0);

	cta = malloc(sizeof(struct cta_info));
	if (!cta) {
		EXIT();
		return 0;
	}

	cta->reason = reason;
	cta->stop_time = stop_time;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTimeout */
	cta->old_timeout = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxInputOctets */
	cta->old_maxInOctets = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxInputOctets);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxOutputOctets */
	cta->old_maxOutOctets = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxOutputOctets);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxTotalOctets */
	cta->old_maxTotalOctets = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxTotalOctets);

	tr069_selcpy(zone, clnt->id);
	zone[4] = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	znt = tr069_get_table_by_selector(zone);
	dm_assert(znt);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
	old_ac = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);
	tr069_selcpy(cta->old_ac, *old_ac);
	old_tag = get_actag_by_selector(*old_ac);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Password */
	radius_authentication_request(zone, znt, clnt->id, clnt,
				      tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId),
				      tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username),
				      tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Password),
				      old_tag, 0, 1,
				      NULL, cta_final_cb, cta);

	EXIT();
	return 1;
}

static void chldtimer_cb(EV_P_ ev_timer *w, int revents __attribute__ ((unused)))
{
	struct tr069_value_table *clnt = w->data;
	struct client_info *ci;

	ticks_t valid = 0;
	ticks_t rt_now = ticks();

	ticks_t timeout;
	ticks_t idle_timeout;

	ticks_t idle = 0;
	ticks_t end = 0;
	ticks_t stop_time = rt_now;

	ENTER();

	w->repeat = 60.;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_ClientInfo */
	ci = tr069_get_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_ClientInfo);
	dm_assert(ci);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
	valid = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ValidTill);
	if (valid != 0) {
		debug("valid: %" PRItick ", now: %" PRItick, valid, rt_now);
		if (valid <= rt_now) {
			stop_session(clnt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Lost_Carrier, rt_now);
			remove_client(clnt);

			EXIT();
			return;
		}
		ticks_t tdiff = valid - rt_now;
		debug("tdiff: %" PRItick, tdiff);
		if ((tdiff / 10.0) < w->repeat)
			w->repeat = tdiff / 10.0;
	}

	timeout = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout);
	if (timeout > 0) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
		end = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime) + timeout;

		if ((end - rt_now) / 10.0 < w->repeat)
			w->repeat = (end - rt_now) / 10.0;
	}

	idle_timeout = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeout);
	if (idle_timeout > 0) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastCounterUpdate */
		idle = rt_now - tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastCounterUpdate);
		if (idle < idle_timeout && (idle_timeout - idle) / 10.0 < w->repeat)
			w->repeat = (idle_timeout - idle) / 10.0;
	}

	if ((end && rt_now >= end) || (idle_timeout && idle >= idle_timeout)) {
		/* stop the current session */
		int r;
		int reason = cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Session_Timeout;

		/*
		 * FIXME: this should be a request_client_accessclass ( or a reauth),
		 *        but the change semantics are not defined yet
		 */
		if (idle_timeout && idle >= idle_timeout)
			reason = cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Idle_Timeout;

		r = 0;
		if (reason == cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Session_Timeout &&
		    tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction) ==
		    cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction_RADIUS_Request)
			r = client_termination_action(clnt, reason, stop_time);

		if (!r)
			exit_client_accessclass(clnt, NULL, reason, stop_time, NULL, NULL);
	} else {
		uint32_t interim;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InterimUpdateInterval */
		interim = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InterimUpdateInterval);

		if (interim != 0) {
			ticks_t tdiff;

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAccountingUpdate */
			tdiff = rt_now - tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAccountingUpdate);
			if (tdiff >= interim) {
				radius_accounting_request(RAD_UPDATE, clnt, 0);
				if (interim / 10.0 < w->repeat)
					w->repeat = interim / 10.0;
			} else if ((interim - tdiff) / 10.0 < w->repeat) {
				w->repeat = (interim - tdiff) / 10.0;
			}
		}
	}

	ev_timer_again(EV_A_ &ci->timer);

	EXIT();
}

static void hs_client_stop_timer(struct client_info *ci)
{
	if (!ci)
		return;

	ev_timer_stop(EV_DEFAULT_ &ci->timer);
}

static int hs_client_timer_running(struct client_info *ci)
{
	if (!ci)
		return 0;

	return ev_is_active(&ci->timer);
}

void scg_client_volume_exhausted(struct tr069_value_table *zone __attribute__((unused)),
				 struct tr069_value_table *clnt, int reason)
{
	int r;
	ticks_t rt_now = ticks();

	ENTER();

	/* stop the current session */

	r = 0;
	if (tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction) ==
	    cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction_RADIUS_Request)
		r = client_termination_action(clnt, reason, rt_now);
	
	if (!r)
		exit_client_accessclass(clnt, NULL, reason, rt_now, NULL, NULL);

	EXIT();
}

static int hs_client_start_timer(struct tr069_value_table *clnt)
{
	struct client_info *ci;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_ClientInfo */
	ci = tr069_get_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_ClientInfo);
	if (!ci) {
		ci = malloc(sizeof(struct client_info));
		if (!ci) {
			EXIT();
			return 0;
		}

		ev_init(&ci->timer, chldtimer_cb);
		ci->timer.data = clnt;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_ClientInfo */
		tr069_set_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_ClientInfo, ci);
	}

	ci->timer.repeat = 60.;
	ev_timer_again(EV_DEFAULT_ &ci->timer);

	EXIT();
	return 1;
}

static void update_client_stats(struct tr069_value_table *clnt, ticks_t rt_now)
{
	ticks_t tdiff = ticks();

	ENTER();

	//iptables_fw_counters_update(clnt->id[2]);

	tdiff = rt_now;
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
	tdiff -= tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime);
	if (tdiff < 0)
		tdiff = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTime */
	tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime, tdiff);

	tdiff = rt_now;
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastCounterUpdate */
	tdiff -= tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastCounterUpdate);
	if (tdiff < 0)
		tdiff = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTime */
	tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTime, tdiff);

	EXIT();
}

int hs_is_enabled(const tr069_selector sel)
{
	struct tr069_value_table *znt;

	znt = hs_get_zone_by_device(sel);
	if (!znt)
		return 0;

	return tr069_get_bool_by_id(znt, cwmp__IGD_SCG_Zone_i_Enabled);
}

/* retrieve client based on IP
 * also make sure the clients tables exists
 */
static struct tr069_instance_node *get_client_by_ip(struct tr069_value_table *znt, struct in_addr addr)
{
#if defined(SDEBUG)
	char ip[INET6_ADDRSTRLEN];
#endif
	struct tr069_value_table *clnts;
	struct tr069_instance *clnt;
	struct tr069_instance_node *node;
	ENTER();

	debug(": zone: %d, addr: %s", znt->id[3], ip2str(addr, ip));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients */
	clnts = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Clients);
	if (!clnts)
		tr069_add_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
					cwmp__IGD_X_TPLINO_NET_SessionControl,
					cwmp__IGD_SCG_Zone,
					znt->id[3],
					cwmp__IGD_SCG_Zone_i_Clients, 0});
	clnts = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Clients);
	if (!clnts) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client */
	clnt = tr069_get_instance_ref_by_id(clnts, cwmp__IGD_SCG_Zone_i_Clnts_Client);

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	node = find_instance(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress, T_IPADDR4, &init_DM_IP4(addr, 0));

	EXIT_MSG(" node: %p", node);
	return node;
}

static struct tr069_instance_node *new_client(struct tr069_value_table *znt, int addr_src, struct in_addr addr, ticks_t rt_now)
{
	struct tr069_instance_node *node;
	struct tr069_value_table *nt;
	tr069_id zn_id = znt->id[3];
	tr069_selector sb;
	struct tr069_value_table *act;
	char sessionid[SESSIONIDSIZE];
	char token[33];
	char *t = token;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.UnknownAccessClass */
	act = get_access_class(*tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_UnknownAccessClass));
	if (!act) {
		debug(": UnknownAccessClass in zone is missing");
		EXIT();
		return NULL;
	}

	tr069_selcpy(sb, znt->id);
	sb[4] = cwmp__IGD_SCG_Zone_i_Clients;
	sb[5] = cwmp__IGD_SCG_Zone_i_Clnts_Client;
	sb[6] = 0;

	tr069_id id = TR069_ID_AUTO_OBJECT;
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
	node = tr069_add_instance_by_selector(sb, &id);
	if (!node) {
		EXIT();
		return NULL;
	}
	nt = DM_TABLE(node->table);

	sb[6] = id;
	sb[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastSession;
	sb[8] = 0;
	tr069_add_table_by_selector(sb);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	tr069_set_ipv4_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress, addr);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddressSource */
	tr069_set_enum_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource, addr_src);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RequestedNATIPAddress */
	tr069_set_ipv4_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATIPAddress, (struct in_addr){ .s_addr = INADDR_NAS_SELECT});

	get_session_id(sessionid, sizeof(sessionid));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
	tr069_set_string_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId, sessionid);

	for (unsigned int i = 1; i < 16 / sizeof(int); i++)
		t += sprintf(t, "%0x", havege_rand(&h_state));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ClientToken */
	tr069_set_string_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ClientToken, token);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.DefaultLocationId */
	t = (char *)tr069_get_string_by_id(znt, cwmp__IGD_SCG_Zone_i_DefaultLocationId);
	if (t)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
		tr069_set_string_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId, t);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.FirstSeen */
	tr069_set_ticks_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_FirstSeen, rt_now);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
	tr069_set_ticks_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime, rt_now);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSeen */
	tr069_set_ticks_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastSeen, rt_now);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastCounterUpdate */
	tr069_set_ticks_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastCounterUpdate, rt_now);

	/* default valid till = 600 seconds */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.KeepAliveTimeout */
	tr069_set_uint_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_KeepAliveTimeout, 600);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
	inc_valid_till(DM_TABLE(node->table), rt_now);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTimeAccounting */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.SessionTimeAccounting */
	tr069_set_enum_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeAccounting,
			     tr069_get_enum_by_id(znt, cwmp__IGD_SCG_Zone_i_SessionTimeAccounting));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitAccessClass */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.ExitAccessClass */
	tr069_set_selector_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitAccessClass,
				 *tr069_get_selector_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_ExitAccessClass));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitRequestAccessClass */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.ExitRequestAccessClass */
	tr069_set_selector_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitRequestAccessClass,
				 *tr069_get_selector_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_ExitRequestAccessClass));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTimeoutRequestAccessClass */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.IdleTimeoutRequestAccessClass */
	tr069_set_selector_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeoutRequestAccessClass,
				 *tr069_get_selector_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_IdleTimeoutRequestAccessClass));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
	tr069_set_selector_by_id(nt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass, act->id);
	fw_allow(zn_id, nt, act);

	EXIT();
	return node;
}

static int hs_update_client_by_zone(struct tr069_value_table *znt,
				    int addr_src, struct in_addr addr, const char *mac,
				    const char *username, const char *password,
				    const char *useragent,
				    const binary_t *agentcircuitid, const binary_t *agentremoteid,
				    const tr069_selector host, ticks_t valid_till,
				    authentication_cb cb, void *user)
{
	ticks_t rt_now = ticks();
	struct tr069_instance_node *node;
	struct tr069_value_table *clnt;
	ticks_t vt_old;
	int new = 0;

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	node = get_client_by_ip(znt, addr);
	if (!node) {
		node = new_client(znt, addr_src, addr, rt_now);
		new = 1;
	}
	if (!node) {
		EXIT();
		return 0;
	}
	clnt = DM_TABLE(node->table);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSeen */
	tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastSeen, rt_now);

	if (mac) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress, mac);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddressSource */
		tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddressSource, addr_src);
	}

	if (username)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username, username);
	if (password)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Password */
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Password, password);
	if (useragent)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.UserAgent */
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_UserAgent, useragent);
	if (agentcircuitid)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentCircuitId */
		tr069_set_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentCircuitId, agentcircuitid);
	if (agentremoteid)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentRemoteId */
		tr069_set_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentRemoteId, agentremoteid);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Host */
	tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Host, host);

	set_valid_till(clnt, valid_till);

	update_instance_node_index(node);

	if (new) {
		/* trigger pre-auth radius request */
		exit_client_accessclass(clnt, username, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Lost_Service, ticks(), cb, user);
	} else if (cb)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAuthenticationResult */
		cb(tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthenticationResult), clnt, user);

	EXIT();
	return 1;
}

int hs_update_client_called_station(struct tr069_value_table *znt,
				    int addr_src, struct in_addr addr, const char *mac, const char *user,
				    const uint8_t *calledstationid, size_t calledstationid_len,
				    const uint8_t *locationid, const uint8_t *relsessid,
				    unsigned int keep_alive_timeout)
{
	ticks_t rt_now = ticks();
	struct tr069_instance_node *node;
	int new = 0;

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	node = get_client_by_ip(znt, addr);
	if (!node) {
		node = new_client(znt, addr_src, addr, rt_now);
		new = 1;
	}
	if (!node) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSeen */
	tr069_set_ticks_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastSeen, rt_now);

	if (mac) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
		const char *m = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress);

		if (!m || !*m) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
			tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress, mac);
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddressSource */
			tr069_set_enum_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddressSource, addr_src);
		}
	}

	if (user)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
		tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username, user);
	if (calledstationid)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.CalledStationId */
		tr069_set_binary_data_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_CalledStationId, calledstationid_len, calledstationid);
	if (locationid)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
		tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId, (const char *)locationid);
	if (relsessid)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RelatedSessionId */
		tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RelatedSessionId, (const char *)relsessid);

	if (keep_alive_timeout != UINT_MAX)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.KeepAliveTimeout */
		tr069_set_uint_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_KeepAliveTimeout, keep_alive_timeout);

	inc_valid_till(DM_TABLE(node->table), rt_now);

	update_instance_node_index(node);

	if (new) {
		/* trigger pre-auth radius request */
		exit_client_accessclass(DM_TABLE(node->table), user, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Lost_Service, ticks(), NULL, NULL);
	}

	EXIT();
	return 1;
}

int hs_update_client_from_sol(tr069_id zone, tr069_id ac,
			      struct in_addr addr, const char *mac,
			      authentication_cb cb, void *user)
{
	int rc;

	struct tr069_value_table	*znt;

	tr069_selector			*sel;
	struct tr069_value_table	*land;

	struct tr069_instance_node	*node;
	struct tr069_value_table	*clnt;

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	znt = hs_get_zone_by_id(zone);
	if (!znt) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.LANDevice */
	sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_LANDevice);
	if (!sel) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i} */
	land = tr069_get_table_by_selector(*sel);
	if (!land) {
		EXIT();
		return 0;
	}

	if (!is_local_ip(land, addr))
		mac = NULL;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
	node = get_client_by_ip(znt, addr);
	if (!node) {
		/* new client - hs_update_client_by_zone cares about access class transition */
		rc = hs_update_client_by_zone(znt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource_SOL, addr, mac,
					      NULL, NULL, NULL, NULL, NULL, NULL, ticks() + time2ticks(600), cb, user);

		EXIT();
		return rc;
	}
	/* old client */
	clnt = DM_TABLE(node->table);

	rc = hs_update_client_by_zone(znt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource_SOL, addr, mac,
				      NULL, NULL, NULL, NULL, NULL, NULL, ticks() + time2ticks(600), NULL, NULL);
	if (!rc) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
	sel = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	if (!sel || (*sel)[6] != ac) {
		EXIT();
		return 0;
	}

	/* trigger auth radius request */
	rc = exit_client_accessclass(clnt, NULL, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Lost_Service, ticks(), cb, user);
	/* callback will be always invoked (rc doesn't matter) */
	debug(": exit_client_accessclass: %d", rc);

	EXIT();
	return 1;
}

int hs_update_client(tr069_id zone,
		     int addr_src, struct in_addr addr, const char *mac,
		     const char *username, const char *password,
		     const char *useragent,
		     const binary_t *agentcircuitid, const binary_t *agentremoteid,
		     const tr069_selector host, ticks_t valid_till)
{
	int rc;
	struct tr069_value_table *znt;

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	znt = hs_get_zone_by_id(zone);
	if (!znt) {
		EXIT();
		return 0;
	}

	rc = hs_update_client_by_zone(znt, addr_src, addr, mac,
				      username, password, useragent, agentcircuitid, agentremoteid, host, valid_till, NULL, NULL);

	EXIT();
	return rc;
}

int hs_update_client_by_device(const tr069_selector sel,
			       int addr_src, struct in_addr addr, const char *mac,
			       const char *username, const char *password,
			       const char *useragent,
			       const binary_t *agentcircuitid, const binary_t *agentremoteid,
			       const tr069_selector host, ticks_t valid_till)
{
	int rc;
	struct tr069_value_table *znt;
#if defined(SDEBUG)
       char b1[128];
#endif

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	debug("(): sel: %s\n", sel2str(b1, sel));

	znt = hs_get_zone_by_device(sel);
	if (!znt) {
		EXIT();
		return 0;
	}
	rc = hs_update_client_by_zone(znt, addr_src, addr, mac,
				      username, password, useragent, agentcircuitid, agentremoteid, host, valid_till, NULL, NULL);

	EXIT();
	return rc;
}

int hs_remove_client_by_zone(struct tr069_value_table *znt, struct in_addr addr, int cause)
{
	struct tr069_instance_node *node;

	ENTER();

	node = get_client_by_ip(znt, addr);
	if (!node) {
		EXIT();
		return 0;
	}

	stop_session(DM_TABLE(node->table), cause, ticks());
	remove_client(DM_TABLE(node->table));

	EXIT();
	return 1;
}

void hs_remove_all_clients_from_zone(struct tr069_value_table *znt, int cause)
{
	struct tr069_value_table *clnts;
	struct tr069_instance *clnt;
	struct tr069_instance_node *node;
	ticks_t rt_now = ticks();

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients */
	clnts = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Clients);
	if (!clnts) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client */
	clnt = tr069_get_instance_ref_by_id(clnts, cwmp__IGD_SCG_Zone_i_Clnts_Client);
	if (!clnt) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
	for (node = tr069_instance_first(clnt);
	     node != NULL;
	     node = tr069_instance_next(clnt, node)) {
		stop_session(DM_TABLE(node->table), cause, rt_now);
		remove_client(DM_TABLE(node->table));
	}
	EXIT();
}

int hs_remove_client(tr069_id zone, struct in_addr addr, int cause)
{
	int rc;
	struct tr069_value_table *znt;

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	znt = hs_get_zone_by_id(zone);
	if (!znt) {
		EXIT();
		return 0;
	}
	rc = hs_remove_client_by_zone(znt, addr, cause);

	EXIT();
	return rc;
}

int hs_remove_client_by_device(const tr069_selector sel, struct in_addr addr, int cause)
{
	int rc;
	struct tr069_value_table *znt;

	ENTER();

	if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
		EXIT();
		return 0;
	}

	znt = hs_get_zone_by_device(sel);
	if (!znt) {
		EXIT();
		return 0;
	}
	rc = hs_remove_client_by_zone(znt, addr, cause);

	EXIT();
	return rc;
}

void del_IGD_SCG_Zone_i_Clnts_Client(const struct tr069_table *kw __attribute__ ((unused)),
				     tr069_id id __attribute__ ((unused)),
				     struct tr069_instance *inst __attribute__ ((unused)),
				     struct tr069_instance_node *node)
{
	struct tr069_value_table *clnt = DM_TABLE(node->table);
	struct client_info *ci;

	ENTER();

	client_set_monitor_target(clnt, NULL, cwmp___IGD_SCG_Mon_i_Type_Manual);
	switch_natpool(clnt, NULL);
	fw_clnt_cleanup(clnt);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_ClientInfo */
	ci = tr069_get_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_ClientInfo);
	if (hs_client_timer_running(ci))
		stop_session(clnt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Lost_Service, ticks());

	free(ci);

	EXIT();
}

/*
 * Stop Session in OLD class
 */
static void stop_session(struct tr069_value_table *base, int cause, ticks_t rt_now)
{
	struct client_info *ci;
	tr069_selector *class;
	struct tr069_value_table *ac;
	struct tr069_value_table *ls;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_ClientInfo */
	ci = tr069_get_ptr_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_ClientInfo);
	if (ci)
		hs_client_stop_timer(ci);

	class = tr069_get_selector_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);
	if (!class || !*class) {
		debug(": can not stop session for client in invalid access class");
		return;
	}

	update_client_stats(base, rt_now);
	if (tr069_get_enum_by_id(base,
				 cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeAccounting) == cwmp___IGD_SCG_Zone_i_SessionTimeAccounting_WISPrCompliant &&
	    (cause == cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Idle_Timeout ||
	     cause == cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Lost_Carrier)) {
		tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime,
				      tr069_get_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime) -
				      tr069_get_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTime));
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	ac = tr069_get_table_by_selector(*class);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccountingEnabled */
	if (ac && tr069_get_bool_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccountingEnabled))
		radius_accounting_request(RAD_STOP, base, cause + 1);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	fw_deny(base->id[3], base, ac);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession */
	ls = tr069_get_table_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastSession);
	if (ls) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.StartTime */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
		tr069_set_ticks_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_StartTime,
				      tr069_get_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.Username */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
		tr069_set_string_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_Username,
				       tr069_get_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.AcctSessionId */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AcctSessionId */
		tr069_set_string_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_AcctSessionId,
				       tr069_get_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.AccessClass */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
		tr069_set_selector_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_AccessClass,
					 *tr069_get_selector_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.InOctets */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InOctets */
		tr069_set_uint64_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_InOctets,
				       tr069_get_uint64_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.InPackets */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InPackets */
		tr069_set_uint_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_InPackets,
				     tr069_get_uint_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InPackets));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.OutOctets */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutOctets */
		tr069_set_uint64_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_OutOctets,
				       tr069_get_uint64_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.OutPackets */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutPackets */
		tr069_set_uint_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_OutPackets,
				     tr069_get_uint_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutPackets));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.SessionTime */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTime */
		tr069_set_ticks_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_SessionTime,
				      tr069_get_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastSession.TerminateCause */
		tr069_set_enum_by_id(ls, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause, cause);
	}
}

static tr069_selector *find_natpool_by_id(const char *poolid)
{
	struct tr069_instance *nps;
	struct tr069_instance_node *np;

	ENTER();

	if (!poolid || !*poolid) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool */
	nps = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_NATPool, 0 });
	if (!nps) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.i.NatPoolId */
	np = find_instance(nps, cwmp__IGD_SCG_NP_i_NatPoolId, T_STR, &init_DM_STRING(poolid, 0));
	if (!np) {
		EXIT();
		return NULL;
	}

	EXIT();
	return &DM_TABLE(np->table)->id;
}

static void start_session(struct tr069_value_table *base,
			  tr069_selector * const class,
			  const char *sessionid)
{
	struct tr069_value_table *act;
	tr069_selector *np;
	ticks_t rt_now = ticks();

	ENTER();

	act = get_access_class(*class);
	if (!act) {
		debug(": can not start session in invalid access class");
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AcctSessionId */
	tr069_set_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId, sessionid);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
	tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime, rt_now);

	/*
	 * wipe all counters
	 */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastCounterUpdate */
	tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastCounterUpdate, rt_now);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InOctets */
	tr069_set_uint64_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets, 0);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InPackets */
	tr069_set_uint_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InPackets, 0);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutOctets */
	tr069_set_uint64_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets, 0);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutPackets */
	tr069_set_uint_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutPackets, 0);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTime */
	tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime, 0);

	/*
	 * Start Session in NEW class
	 */
	fw_allow(base->id[3], base, act);

	np = find_natpool_by_id(tr069_get_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATPoolId));
	if (!np)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.NATPool */
		np = tr069_get_selector_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_NATPool);

	if (!np) {
		tr069_selector sel;

		tr069_selcpy(sel, base->id);
		sel[4] = cwmp__IGD_SCG_Zone_i_NATPool;
		sel[5] = 0;
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.NATPool */
		np = tr069_get_selector_by_selector(sel);
	}
	switch_natpool(base, np);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccountingEnabled */
	if (tr069_get_bool_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccountingEnabled))
		radius_accounting_request(RAD_START, base, 0);
	else
		tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InterimUpdateInterval, 0);

	hs_client_start_timer(base);

	EXIT();
}

struct rca_data {
	char sessionid[SESSIONIDSIZE];
	int cause;

	authentication_cb cb;
	void *user;
};

static void rca_final_cb(int res, struct tr069_value_table *clnt, void *user)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct rca_data *rca = user;

	ENTER();

	/* if successfull: */
	/* terminate old session */
	/* start new session */

	debug("(): Client: %p (%s), Res: %d\n", clnt, clnt ? sel2str(b1, clnt->id) : "(NULL)", res);

	if (clnt && res == AUTH_STATE_ACCEPTED) {
		start_session(clnt, tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass),
			      rca->sessionid);
	}

	if (rca->cb)
		rca->cb(res, clnt, rca->user);
	free(rca);

	EXIT();
}

static void auth_ok_cb(int res __attribute__ ((unused)),
		       struct tr069_value_table *clnt, void *user)
{
	struct rca_data *rca = user;

	ENTER();

	stop_session(clnt, rca->cause, ticks());

	EXIT();
}

static int start_client_authentication(struct tr069_value_table *znt, struct tr069_value_table *clnt,
				       const char *sessionid, const char *username, const char *password, const char *tag, int cause,
				       const char *user_agent,
				       authentication_cb cb, void *user)
{
	int rc;
	struct rca_data *rca = NULL;

	/* send Auth request */

	ENTER();

	rca = malloc(sizeof(struct rca_data));
	if (!rca) {
		EXIT();
		return -1;
	}

	if (user_agent && *user_agent)
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_UserAgent, user_agent);

	rca->cause = cause;
	rca->cb = cb;
	rca->user = user;
	strncpy(rca->sessionid, sessionid, sizeof(rca->sessionid));

	rc = radius_authentication_request(znt->id, znt, clnt->id, clnt,
					   sessionid, username, password, tag, 0, 0,
					   auth_ok_cb, rca_final_cb, rca);

	EXIT();
	return rc;
}

static int _request_client_accessclass(struct tr069_value_table *clnt,
				       const char *username, const char *password, const char *tag, int cause,
				       const char *user_agent,
				       authentication_cb cb, void *user)
{
	int rc;
	tr069_selector zone;
	struct tr069_value_table *znt;
	char id_buf[SESSIONIDSIZE];
	const char *sessionid;

	/* send Auth request */

	ENTER();

	sessionid = get_acct_session_id(clnt, id_buf, sizeof(id_buf));

	tr069_selcpy(zone, clnt->id);
	zone[4] = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	znt = tr069_get_table_by_selector(zone);
	dm_assert(znt);

	rc = start_client_authentication(znt, clnt,
					 sessionid, username, password, tag, cause, user_agent,
					 cb, user);

	EXIT();
	return rc;
}

static struct tr069_value_table *get_accessclass_by_tag(const tr069_selector zone,
							const char *tag)
{
	tr069_selector acsel;
	struct tr069_instance *acs;
	struct tr069_instance_node *ac = NULL;
	struct tr069_value_table *act = NULL;

	if (zone[0] != cwmp__InternetGatewayDevice ||
	    zone[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    zone[2] != cwmp__IGD_SCG_Zone ||
	    zone[3] == 0)
		return NULL;

	tr069_selcpy(acsel, zone);
	acsel[4] = cwmp__IGD_SCG_Zone_i_AccessClasses;
	acsel[5] = cwmp__IGD_SCG_Zone_i_ACs_AccessClass;
	acsel[6] = 0;

	/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass */
	acs = tr069_get_instance_ref_by_selector(acsel);
	if (acs) {
		/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
		/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
		ac = find_instance(acs, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId, T_STR, &init_DM_STRING(tag, 0));
		if (ac)
			act = DM_TABLE(ac->table);
	}

	debug(": got act: %p\n", act);

	return act;
}

/* forcefully leave a AC, move to Exit-AC and request the ExitRequestAC */
static int exit_client_accessclass(struct tr069_value_table *clnt, const char *username, int cause, ticks_t rt_now,
				   authentication_cb cb, void *user)
{
	int rc = 0;

	tr069_selector *new;
	tr069_selector *req = NULL;
	struct tr069_value_table *act;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitAccessClass */
	new = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitAccessClass);
	if (!new || !*new) {
		tr069_selector zone;

		tr069_selcpy(zone, clnt->id);
		zone[4] = cwmp__IGD_SCG_Zone_i_KnownAccessClass;
		zone[5] = 0;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.KnownAccessClass */
		new = tr069_get_selector_by_selector(zone);
	}

	switch (cause) {
	case cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_Idle_Timeout:
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTimeoutRequestAccessClass */
		req = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeoutRequestAccessClass);
		break;
	}

	if (!req || !*req)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitRequestAccessClass */
		req = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitRequestAccessClass);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	act = get_access_class(*req);
	if (act) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AuthorizationRequired */
		if (tr069_get_bool_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AuthorizationRequired)) {
			set_client_accessclass(clnt, username, *new, cause, NULL, rt_now);
			rc = _request_client_accessclass(clnt, username, NULL,
							 /** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
							 tr069_get_string_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId),
							 cause, NULL, cb, user);
			EXIT();
			return rc;
		}

		/* requested AC exists, but does not need authorization */
		new = req;
	}

	rc = set_client_accessclass(clnt, username, *new, cause, NULL, rt_now);
	if (cb)
		cb(AUTH_STATE_ACCEPTED, clnt, user);
	return rc;
}

int scg_req_client_accessclass(const tr069_selector sel,
			       const char *username, const char *password, char *tag, int cause,
			       const char *user_agent,
			       authentication_cb cb, void *user)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct tr069_value_table *clnt;
	struct tr069_value_table *act = NULL;

	debug("(): Client: %s, User-Agent: %s Tag: %s\n",
	      sel2str(b1, sel), user_agent ? user_agent : "NULL", tag ? tag : "NULL");

	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    sel[2] != cwmp__IGD_SCG_Zone ||
	    sel[3] == 0 ||
	    sel[4] != cwmp__IGD_SCG_Zone_i_Clients ||
	    sel[5] != cwmp__IGD_SCG_Zone_i_Clnts_Client ||
	    sel[6] == 0 ||
	    sel[7] != 0)
		return -1;

	clnt = tr069_get_table_by_selector(sel);
	if (!clnt)
		return -1;

	if (tag)
		act = get_accessclass_by_tag(sel, tag);
	if (!act) {
		tr069_selector *st;
		tr069_selector zone;

		tr069_selcpy(zone, sel);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.OnlineAccessClass */
		zone[4] = cwmp__IGD_SCG_Zone_i_OnlineAccessClass;
		zone[5] = 0;

		st = tr069_get_selector_by_selector(zone);
		if (st)
			act = tr069_get_table_by_selector(*st);
	}
	/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AuthorizationRequired */
	if (!act || tr069_get_bool_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AuthorizationRequired))
		return _request_client_accessclass(clnt, username, password, tag, cause, user_agent, cb, user);
	else {
		int rc;

		rc = set_client_accessclass(clnt, username, act->id, cause, user_agent, ticks());
		if (cb)
			cb(AUTH_STATE_ACCEPTED, clnt, user);
		return rc;
	}
}


static int _set_client_accessclass(struct tr069_value_table *base, const char *username,
				   DM_VALUE *st, DM_VALUE val, int cause, const char *user_agent, ticks_t rt_now)
{
#if defined(SDEBUG)
	char b1[128], b2[128];
#endif
	char id_buf[SESSIONIDSIZE];
	const char *sessionid;

        ENTER();

        debug(": AccessClass, old: %s, new: %s\n", sel2str(b1, *DM_SELECTOR(*st)), sel2str(b2, *DM_SELECTOR(val)));

	if (!DM_SELECTOR(val)) {
		EXIT();
		return 0;
	}

	if (DM_SELECTOR(*st) && DM_SELECTOR(val) &&
	    tr069_selcmp(*DM_SELECTOR(*st), *DM_SELECTOR(val), TR069_SELECTOR_LEN) == 0) {
		EXIT();
		return 0;
	}

	stop_session(base, cause, rt_now);

	tr069_set_selector_value(st, *DM_SELECTOR(val));

	if (user_agent && *user_agent)
		tr069_set_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_UserAgent, user_agent);

	if (username && *username) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
		tr069_set_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username, username);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Password */
		tr069_set_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Password, NULL);
	}

	/* TODO: pass AAA-Provider and AAA-Results
	 *
	 * wipe them for now
	 */

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationProvider */
	tr069_set_enum_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationProvider, AUTH_PROV_NONE);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthorizationProvider */
	tr069_set_enum_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthorizationProvider, AUTH_PROV_NONE);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAuthenticationResult */
	tr069_set_enum_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthenticationResult, AUTH_STATE_NONE);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthorizationResult */
	tr069_set_enum_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthorizationResult, AUTH_STATE_NONE);

	struct tr069_value_table *ac;

	ac = tr069_get_table_by_selector(*DM_SELECTOR(*st));
	if (ac) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTimeout */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.SessionTimeout */
		tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout,
				      time2ticks(tr069_get_uint_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_SessionTimeout)));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTimeout */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.IdleTimeout */
		tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeout,
				      time2ticks(tr069_get_uint_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_IdleTimeout)));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InterimUpdateInterval */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.InterimUpdateInterval */
		tr069_set_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InterimUpdateInterval,
				      time2ticks(tr069_get_uint_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_InterimUpdateInterval)));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitAccessClass */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.ExitAccessClass */
		tr069_set_selector_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitAccessClass,
					 *tr069_get_selector_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_ExitAccessClass));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitRequestAccessClass */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.ExitRequestAccessClass */
		tr069_set_selector_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitRequestAccessClass,
					 *tr069_get_selector_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_ExitRequestAccessClass));

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTimeoutRequestAccessClass */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.IdleTimeoutRequestAccessClass */
		tr069_set_selector_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeoutRequestAccessClass,
					 *tr069_get_selector_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_IdleTimeoutRequestAccessClass));
	}

	/* NOTE: DM_SELECTOR(val) might be destroyed at this point if it was a pointer to ExitAccessClass or ExitRequestAccessClass !!! */

	sessionid = get_acct_session_id(base, id_buf, sizeof(id_buf));
	start_session(base, &ac->id, sessionid);

	EXIT();
	return 0;
}

int set_IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass(struct tr069_value_table *base,
						tr069_id id __attribute__ ((unused)),
						const struct tr069_element *elem __attribute__ ((unused)),
						DM_VALUE *st,
						DM_VALUE val)
{
	return _set_client_accessclass(base, NULL, st, val, 0, NULL, ticks());
}


static int set_client_accessclass(struct tr069_value_table *client, const char *username,
				  const tr069_selector ac, int cause, const char *user_agent, ticks_t rt_now)
{
	int rc;
	DM_VALUE *st;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
	st = tr069_get_value_ref_by_id(client, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);

	rc = _set_client_accessclass(client, username, st, init_DM_SELECTOR(ac, 0), cause, user_agent, rt_now);
	tr069_notify_by_id(client, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);

	EXIT();
	return rc;
}

int scg_set_client_accessclass(const tr069_selector sel, const char *username, char *tag, int cause, const char *user_agent)
{
	struct tr069_value_table *clnt;
	struct tr069_value_table *act;

	if (sel[0] != cwmp__InternetGatewayDevice ||
	    sel[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    sel[2] != cwmp__IGD_SCG_Zone ||
	    sel[3] == 0 ||
	    sel[4] != cwmp__IGD_SCG_Zone_i_Clients ||
	    sel[5] != cwmp__IGD_SCG_Zone_i_Clnts_Client ||
	    sel[6] == 0 ||
	    sel[7] != 0)
		return -1;

	clnt = tr069_get_table_by_selector(sel);
	if (!clnt)
		return -1;

	act = get_accessclass_by_tag(clnt->id, tag);
	if (!act) {
		EXIT();
		return -1;
	}

	return set_client_accessclass(clnt, username, act->id, cause, user_agent, ticks());
}

DM_VALUE get_IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime(const struct tr069_value_table *base,
						     tr069_id id __attribute__ ((unused)),
						     const struct tr069_element *elem __attribute__ ((unused)),
						     DM_VALUE val)
{
	ticks_t tdiff = ticks();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
	tdiff -= tr069_get_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime);
	if (tdiff < 0)
		tdiff = 0;

	set_DM_TICKS(val, tdiff);

	return val;
}

DM_VALUE get_IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTime(const struct tr069_value_table *base,
						  tr069_id id __attribute__ ((unused)),
						  const struct tr069_element *elem __attribute__ ((unused)),
						  DM_VALUE val)
{
	ticks_t tdiff = ticks();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastCounterUpdate */
	tdiff -= tr069_get_ticks_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastCounterUpdate);
	if (tdiff < 0)
		tdiff = 0;

	set_DM_TICKS(val, tdiff);

	return val;
}

void dm_clnt_timer_rearm_action(const tr069_selector sel,
				enum dm_action_type action __attribute__ ((unused)))
{
	struct tr069_value_table *clnt;
	struct client_info *ci;

#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER();

	debug("(): sel: %s\n", sel2str(b1, sel));
	
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
	clnt = tr069_get_table_by_selector(sel);
	if (!clnt) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_ClientInfo */
	ci = tr069_get_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_ClientInfo);
	if (hs_client_timer_running(ci))
		chldtimer_cb(EV_DEFAULT_ &ci->timer, 0);
	
	EXIT();
}
