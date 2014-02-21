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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <net/if.h>
#include <unistd.h>
#include <ev.h>

#define SDEBUG 1
#include "debug.h"
#include "list.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_action.h"

#include "ifup.h"
#include "lng.h"
#include "dhcp.h"
#include "inet_helper.h"
#include "process.h"

#define L2TPD		"/usr/sbin/openl2tpd"
#define L2TPD_CONF	"/var/etc/openl2tpd.conf"
#define L2TPD_PID	"/var/run/openl2tpd.pid"

#define L2TPD_TRACE	"1023" /* ALL except ppp_control */

#define LNG_TABLE	2
#define AC_IF_PRIO	500

#define KILL_TIMEOUT	10. /* seconds */

#define KIBIT(X)	((X) * 1024)

static int l2tpd_id = -1;
static ev_timer kill_timeout;

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	if (ipaddr.s_addr != INADDR_ANY && ipaddr.s_addr != INADDR_NONE)
		return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
	return NULL;
}
static int write_l2tpd_config(void)
{
	FILE *fout;
	struct tr069_value_table *lng;
	struct tr069_instance *tnl;
	struct tr069_instance_node *node;
	unsigned int auth;
	tr069_selector *lansel;
	const char *lan;
	unsigned int mtu;
	const char *hostname;
	const char *user;
	const char *passwd;
	unsigned int tunnel_retry, session_retry, hello_to;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway */
	lng = tr069_get_table_by_selector((tr069_selector) {
					  cwmp__InternetGatewayDevice,
					  cwmp__IGD_X_TPLINO_NET_NetworkGateway,
					  0});
	if (!lng) {
		EXIT();
		return -1;
	}

	vasystem("ip rule del priority %d", AC_IF_PRIO);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Enabled */
	if (!tr069_get_bool_by_id(lng, cwmp__IGD_LNG_Enabled)) {
		EXIT();
		return -1;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.LANDevice */
	lansel = tr069_get_selector_by_id(lng, cwmp__IGD_LNG_LANDevice);
	if (!lansel) {
		EXIT();
		return -1;
	}
	lan = get_if_device(*lansel);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.TunnelHostName */
	hostname = tr069_get_string_by_id(lng, cwmp__IGD_LNG_TunnelHostName);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Username */
	user = tr069_get_string_by_id(lng, cwmp__IGD_LNG_Username);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Password */
	passwd = tr069_get_string_by_id(lng, cwmp__IGD_LNG_Password);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel */
	tnl = tr069_get_instance_ref_by_id(lng, cwmp__IGD_LNG_Tunnel);
	if (!lan || !hostname || !user || !passwd || !tnl) {
		EXIT_MSG(": lan: %p, hostname: %p, user: %p, passwd: %p, tnl: %p",
			 lan, hostname, user, passwd, tnl);
		return -1;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.PPPAuthenticationProtocol */
	auth = tr069_get_enum_by_id(lng, cwmp__IGD_LNG_PPPAuthenticationProtocol);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.MTU */
	mtu = tr069_get_uint_by_id(lng, cwmp__IGD_LNG_MTU);
	if (mtu > 1460)
		mtu = 1460;
	if (mtu == 0)
		mtu = 1442;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.TunnelRetryInterval */
	tunnel_retry = tr069_get_uint_by_id(lng, cwmp__IGD_LNG_TunnelRetryInterval);
	if (tunnel_retry == 0)
		tunnel_retry = 15;
	else if (tunnel_retry < 10)
		tunnel_retry = 10;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.SessionRetryInterval */
	session_retry = tr069_get_uint_by_id(lng, cwmp__IGD_LNG_SessionRetryInterval);
	if (session_retry == 0)
		session_retry = 15;
	else if (session_retry < 10)
		session_retry = 10;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.KeepaliveTimeout */
	hello_to = tr069_get_uint_by_id(lng, cwmp__IGD_LNG_KeepaliveTimeout);

	fout = fopen(L2TPD_CONF, "w");
	if (!fout) {
		EXIT();
		return -1;
	}

	fprintf(fout, "system modify deny_remote_tunnel_creates=yes \\\n"
		"\ttunnel_persist_pend_timeout=%u \\\n"
		"\tsession_persist_pend_timeout=%u\n\n"
		"ppp profile create profile_name=lng \\\n"
		"\ttrace_flags=%s \\\n"
		"\tmultilink=yes \\\n"
		"\tlcp_echo_failure_count=0 \\\n"
		"\tlcp_echo_interval=60 \\\n"
		"\tmtu=%d mru=%d \\\n"
		"\tauth_none=no %s%sauth_eap=no %s%s\n\n"
		"tunnel profile create profile_name=lng \\\n"
		"\ttrace_flags=%s \\\n"
		"\thost_name=\"%s\" \\\n"
		"\tppp_profile_name=lng \\\n"
		"\thello_timeout=%u\n\n"
		"session profile create profile_name=lng \\\n"
		"\ttrace_flags=%s \\\n"
		"\tppp_profile_name=lng\n\n",
		tunnel_retry, session_retry,
		L2TPD_TRACE,
		mtu, mtu,
		auth ==	cwmp___IGD_LNG_PPPAuthenticationProtocol_PAP ? "" : "auth_pap=no ",
		auth ==	cwmp___IGD_LNG_PPPAuthenticationProtocol_CHAP ? "" : "auth_chap=no ",
		auth ==	cwmp___IGD_LNG_PPPAuthenticationProtocol_MS_CHAP ? "" :	"auth_mschapv1=no ",
		auth ==	cwmp___IGD_LNG_PPPAuthenticationProtocol_MS_CHAP_V2 ? "" : "auth_mschapv2=no ",
		L2TPD_TRACE,
		hostname, hello_to,
		L2TPD_TRACE);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i} */
	for (node = tr069_instance_first(tnl);
	     node != NULL;
	     node = tr069_instance_next(tnl, node))
	{
		char ipbuf[INET_ADDRSTRLEN];
		const char *ip;

		unsigned int rxspeed, txspeed;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i}.Enabled */
		if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LNG_Tunnel_i_Enabled))
			continue;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i}.LNSIPAddress */
		ip = ip2str(tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LNG_Tunnel_i_LNSIPAddress), ipbuf);
		if (!ip)
			continue;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i}.RxLinkSpeed */
		rxspeed = tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_LNG_Tunnel_i_RxLinkSpeed);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i}.TxLinkSpeed */
		txspeed = tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_LNG_Tunnel_i_TxLinkSpeed);

		fprintf(fout, "tunnel create \\\n"
			"\tprofile_name=lng \\\n"
			"\ttunnel_name=lng%d \\\n"
			"\tdest_ipaddr=%s \\\n"
			"\tpersist=yes\n\n"
			"session create \\\n"
			"\tprofile_name=lng \\\n"
			"\ttunnel_name=lng%d \\\n"
			"\tsession_name=lng%d \\\n"
			"\tconnect_speed=%u:%u \\\n"
			"\tuser_name=\"%s\" \\\n"
			"\tuser_password=\"%s\"\n\n",
			node->instance,
			ip,
			node->instance,
			node->instance,
			KIBIT(rxspeed),	/* rx/txspeed is in kibit/s */
			KIBIT(txspeed),
			user, passwd);
	}

	fclose(fout);

	vasystem("ip rule add iif %s priority %d table %d", lan, AC_IF_PRIO,
		 LNG_TABLE);

	EXIT();
	return 0;
}

static enum process_action
l2tpd_reaped_cb(struct process_info_t *p __attribute__((unused)),
		enum process_state state,
		int status __attribute__((unused)),
		void *ud __attribute__((unused)))
{
	unlink(L2TPD_PID);

	switch (state) {
	case PROCESS_RUNNING:
		/* undesired crash */

		return PROCESS_RESTART;
	case PROCESS_DYING:
		/* process died after kill_supervise */

		ev_timer_stop(EV_DEFAULT_UC_ &kill_timeout);

		if (write_l2tpd_config()) { /* disabled / error */
			l2tpd_id = -1;
			return PROCESS_REMOVE;
		}

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.ConnectionStatus */
		tr069_set_enum_by_selector((tr069_selector) {
			cwmp__InternetGatewayDevice,
			cwmp__IGD_X_TPLINO_NET_NetworkGateway,
			cwmp__IGD_LNG_ConnectionStatus, 0
		}, cwmp___IGD_LNG_ConnectionStatus_Connecting, DV_UPDATED);

		return PROCESS_RESTART;
	default:
		break;
	}

	/* shouldn't be reached */
	return PROCESS_NOTHING;
}

/*
 * timeout after graceful shutdown
 */
static void kill_timeout_cb(EV_P __attribute__((unused)),
			    ev_timer *w __attribute__((unused)),
			    int revents __attribute__((unused)))
{
	if (l2tpd_id > 0) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.ConnectionStatus */
		tr069_set_enum_by_selector((tr069_selector) {
			cwmp__InternetGatewayDevice,
			cwmp__IGD_X_TPLINO_NET_NetworkGateway,
			cwmp__IGD_LNG_ConnectionStatus, 0
		}, cwmp___IGD_LNG_ConnectionStatus_Disconnected, DV_UPDATED);

		/* DIE! */
		kill_supervise(l2tpd_id, SIGKILL);
	}
}

void init_l2tpd(void)
{
	ENTER();

	insmod("slhc");
	insmod("ppp_generic");
	insmod("pppox");
	insmod("pppol2tp");

	insmod("xt_TCPMSS");

	vasystem("ip route add unreachable default table %d", LNG_TABLE);
	vsystem("iptables -t mangle -A FORWARD -o ppp+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu");

	ev_init(&kill_timeout, kill_timeout_cb);

	EXIT();
}

/*
 * called from ppp hotplug
 */
int lng_ipup(const char *device, const tr069_selector sel)
{
	struct in_addr dst;
	struct in_addr src;
	char ipbuf[INET_ADDRSTRLEN];
	char ip2buf[INET_ADDRSTRLEN];
	const char *ip, *ip2;
	struct tr069_value_table *lng;

	ENTER();

	if_add2ifmap(device, sel);

	dst = getifdstip(device);
	src = getifip(device);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway */
	lng = tr069_get_table_by_selector(sel);
	if (lng) {
		tr069_selector *land;
		struct tr069_instance *tunnel;
		struct tr069_instance_node *tn;
		long tx_speed = 0;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.LocalIPAddress */
		tr069_set_ipv4_by_id(lng, cwmp__IGD_LNG_LocalIPAddress, src);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.RemoteIPAddress */
		tr069_set_ipv4_by_id(lng, cwmp__IGD_LNG_RemoteIPAddress, dst);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.ConnectionStatus */
		tr069_set_enum_by_id(lng, cwmp__IGD_LNG_ConnectionStatus, cwmp___IGD_LNG_ConnectionStatus_Connected);

		land = tr069_get_selector_by_id(lng, cwmp__IGD_LNG_LANDevice);
		if (land)
			dhcp_update_wan_ip(device, *land);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i} */
		tunnel = tr069_get_instance_ref_by_id(lng, cwmp__IGD_LNG_Tunnel);
		if (tunnel) {
			for (tn = tr069_instance_first(tunnel);
			     tn != NULL;
			     tn = tr069_instance_next(tunnel, tn))
			{
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i}.Enabled */
				if (tr069_get_bool_by_id(DM_TABLE(tn->table), cwmp__IGD_LNG_Tunnel_i_Enabled))
					/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.Tunnel.{i}.TxLinkSpeed */
					tx_speed += tr069_get_uint_by_id(DM_TABLE(tn->table), cwmp__IGD_LNG_Tunnel_i_TxLinkSpeed);
			}
		}
		if (tx_speed > 0) {
			unsigned long avpkt = 1500;
			unsigned long latency = 100; /* 100ms */
			unsigned long max = round((KIBIT(tx_speed) / 8 * latency) / 1000.0);
			unsigned long min = round(max / 3.0);
			unsigned long limit = 8 * max;
			unsigned long burst = round((2 * min + max) / (3.0 * avpkt));

			if (min < avpkt)
				min = avpkt;

			vasystem("tc qdisc add dev %s root handle 1: tbf rate %fkbit limit %ld burst 5000 mtu 1520",
				 device, KIBIT(tx_speed) / 1000.0, avpkt);
			vasystem("tc qdisc add dev %s parent 1: handle 10: red "
				 "limit %lu min %lu max %lu avpkt %lu "
				 "burst %lu probability 0.02 bandwidth %fkbit ecn",
				 device, limit, min, max, avpkt, burst, KIBIT(tx_speed) / 1000.0);
			/*
			vasystem("tc qdisc add dev %s parent 10: esfq perturb 10 hash src", device);
			*/
		}
	}

	ip = ip2str(dst, ipbuf);
	if (ip) {
		int rc;

		rc = vasystem("ip route change default via %s table %d", ip, LNG_TABLE);
		if (rc != 0)
			vasystem("ip route add default via %s table %d", ip, LNG_TABLE);

		/* install a /24 route from the local LNG to the remote LNS network */
		dst.s_addr &= htonl(IN_CLASSC_NET);
		ip2 = ip2str(dst, ip2buf);
		if (ip2)
			vasystem("ip route add %s/24 via %s", ip2, ip);

		ip2 = ip2str(src, ip2buf);
		if (ip2)
			vasystem("ip rule add from %s table %d", ip2, LNG_TABLE);
	}

	EXIT();
	return 1;
}

int lng_ipdown(const char *device __attribute__((unused)), const tr069_selector sel)
{
	int rc;
	struct tr069_value_table *lng;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway */
	lng = tr069_get_table_by_selector(sel);
	if (lng) {
		struct in_addr src;
		char ipbuf[INET_ADDRSTRLEN];
		const char *ip;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.LocalIPAddress */
		src = tr069_get_ipv4_by_id(lng, cwmp__IGD_LNG_LocalIPAddress);
		tr069_set_ipv4_by_id(lng, cwmp__IGD_LNG_LocalIPAddress, (struct in_addr){ .s_addr = INADDR_NONE });

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.RemoteIPAddress */
		tr069_set_ipv4_by_id(lng, cwmp__IGD_LNG_RemoteIPAddress, (struct in_addr){ .s_addr = INADDR_NONE });
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.ConnectionStatus */
		tr069_set_enum_by_id(lng, cwmp__IGD_LNG_ConnectionStatus, cwmp___IGD_LNG_ConnectionStatus_Disconnected);

		ip = ip2str(src, ipbuf);
		if (ip)
			vasystem("ip rule del from %s table %d", ip, LNG_TABLE);
	}

	/* the ppp interface will normaly already be gone and the old route with it */
	rc = vasystem("ip route add unreachable default table %d", LNG_TABLE);
	if (rc != 0)
		vasystem("ip route change unreachable default table %d", LNG_TABLE);

	EXIT();
	return 1;
}

void reconf_l2tpd(void)
{
	const char *const argv[] = {L2TPD, "-f", "-c", L2TPD_CONF, "-u", "1701",
#if defined(SDEBUG)
				    "-d", L2TPD_TRACE,
#endif
				    NULL};

	ENTER();

	if (l2tpd_id < 0) {
		if (write_l2tpd_config()) { /* error / disabled */
			EXIT();
			return;
		}

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.ConnectionStatus */
		tr069_set_enum_by_selector((tr069_selector) {
			cwmp__InternetGatewayDevice,
			cwmp__IGD_X_TPLINO_NET_NetworkGateway,
			cwmp__IGD_LNG_ConnectionStatus, 0
		}, cwmp___IGD_LNG_ConnectionStatus_Connecting, DV_UPDATED);

		l2tpd_id = supervise_cb(argv, PROCESS_DEFAULT_MAX_RESTARTS,
			    		PROCESS_DEFAULT_RESTART_TIMESPAN,
			    		l2tpd_reaped_cb, NULL);
	} else {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.ConnectionStatus */
		tr069_set_enum_by_selector((tr069_selector) {
			cwmp__InternetGatewayDevice,
			cwmp__IGD_X_TPLINO_NET_NetworkGateway,
			cwmp__IGD_LNG_ConnectionStatus, 0
		}, cwmp___IGD_LNG_ConnectionStatus_Disconnecting, DV_UPDATED);

		ev_timer_stop(EV_DEFAULT_UC_ &kill_timeout);
		ev_timer_set(&kill_timeout, KILL_TIMEOUT, 0.);
		ev_timer_start(EV_DEFAULT_UC_ &kill_timeout);

		/* graceful shutdown */
		kill_supervise(l2tpd_id, SIGTERM);
	}

	EXIT();
}

void dm_l2tp_reconf_action(const tr069_selector sel,
			   enum dm_action_type type __attribute__((unused)))
{
#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER(": Entering L2TP reconfiguration by trigger: %s",
	      tr069_sel2name(sel, b1, sizeof(b1)));

	if (!test_system_up()) {
		EXIT_MSG(": called before 'system up' time");
		return;
	}

	reconf_l2tpd();

	EXIT();
}
