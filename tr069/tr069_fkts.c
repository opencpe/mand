/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <ares.h>
#include <ev.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_luaif.h"
#include "tr069_ping.h"
#include "tr069_trace.h"
#include "tr069_capture.h"
#include "tr069_validate.h"
#include "tr069_event_queue.h"

#include "utils/logx.h"

#include "ifup.h"
#include "inet_helper.h"
#include "process.h"
#include "cares-ev.h"
#include "tr069_async_resolve.h"

#include "proxy.h"

#define SDEBUG
#include "debug.h"

#define TZ_FILE "/var/etc/TZ"

	/* workaround: symbol is referenced in tr069_dmconfig.c, so the linker
	   will include tr069_fkts even if libtr069 is created as a static lib by
	   libtool and it processes p_table_stubs first */
char tr069_fkts_dummy_dependency;

static int
writeBinaryValue(const char *filename, DM_VALUE *st, DM_VALUE val)
{
	FILE *file;
	int r;

	ENTER();

	if (!DM_BINARY(val) || !DM_BINARY(val)->len) {
		unlink(filename);
		EXIT();
		return tr069_set_binary_value(st, NULL) != DM_OK;
	}

	if (!(file = fopen(filename, "w"))) {
		EXIT();
		return -1;
	}

	r = !fwrite(DM_BINARY(val)->data, DM_BINARY(val)->len, 1, file) ||
	    tr069_set_binary_value(st, DM_BINARY(val)) != DM_OK;

	fclose(file);

	EXIT();
	return r;
}

int set_IGD_HTTPSrvs_SSL_Certificate(struct tr069_value_table *base __attribute__ ((unused)),
				     tr069_id id __attribute__ ((unused)),
				     const struct tr069_element *elem __attribute__ ((unused)),
				     DM_VALUE *st, DM_VALUE val)
{
	return writeBinaryValue(LUCITTPD_SSL_CRT, st, val);
}

int set_IGD_HTTPSrvs_SSL_Key(struct tr069_value_table *base __attribute__ ((unused)),
			     tr069_id id __attribute__ ((unused)),
			     const struct tr069_element *elem __attribute__ ((unused)),
			     DM_VALUE *st, DM_VALUE val)
{
	return writeBinaryValue(LUCITTPD_SSL_KEY, st, val);
}

int set_IGD_HTTPSrvs_SSL_CA_Certificate(struct tr069_value_table *base __attribute__ ((unused)),
					tr069_id id __attribute__ ((unused)),
					const struct tr069_element *elem __attribute__ ((unused)),
					DM_VALUE *st, DM_VALUE val)
{
	return writeBinaryValue(LUCITTPD_SSL_CA, st, val);
}

int set_IGD_DevInf_X_TPLINO_LoggingEnabled(struct tr069_value_table *base __attribute__ ((unused)),
					   tr069_id id __attribute__ ((unused)),
					   const struct tr069_element *elem __attribute__ ((unused)),
					   DM_VALUE *st,
					   DM_VALUE val)
{
	ENTER();

	if (DM_BOOL(*st) != DM_BOOL(val)) {
		logx_level = DM_BOOL(val) ? LOG_DEBUG : LOG_NOTICE;

		toggle_proxy();
	}

	set_DM_BOOL(*st, DM_BOOL(val));

	EXIT();
	return 0;
}

DM_VALUE get_IGD_WANDev_i_ConDev_j_IPCon_k_ExternalIPAddress(const struct tr069_value_table *base __attribute__ ((unused)),
							     tr069_id id __attribute__ ((unused)),
							     const struct tr069_element *elem __attribute__ ((unused)),
							     DM_VALUE val)
{
	int iat;
	DM_VALUE ret = init_DM_IP4({INADDR_NONE}, 0);

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.AddressingType */
	iat = tr069_get_enum_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							   cwmp__IGD_WANDevice,
							   1,
							   cwmp__IGD_WANDev_i_WANConnectionDevice,
							   1,
							   cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection,
							   1,
							   cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_AddressingType, 0 });

	debug("(): iat: %d\n", iat);
	if (iat == 0) {
		const char *device;

		/** VAR: InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1 */
		device = get_if_device((tr069_selector){ cwmp__InternetGatewayDevice,
							 cwmp__IGD_WANDevice,
							 1,
							 cwmp__IGD_WANDev_i_WANConnectionDevice,
							 1, 0 });
		debug("(): wan device: %s\n", device);
		if (device) {
			set_DM_IP4(ret, getifip(device));

			debug("(): ip: %s\n", inet_ntoa(DM_IP4(ret)));
			EXIT();
			return ret;
		}
	}

	EXIT();
	return val;
}

DM_VALUE get_IGD_WANDev_i_ConDev_j_PPPCon_k_Uptime(const struct tr069_value_table *base __attribute__ ((unused)),
						   tr069_id id __attribute__ ((unused)),
						   const struct tr069_element *elem __attribute__ ((unused)),
						   DM_VALUE val)
{
	time_t now;
	DM_VALUE ret = init_DM_UINT(0, 0);

	now = monotonic_time();
	if (DM_UINT(val) <= now)
		set_DM_UINT(ret, now - DM_UINT(val));

	return ret;
}

DM_VALUE get_IGD_DevInf_UpTime(const struct tr069_value_table *base __attribute__ ((unused)),
			       tr069_id id __attribute__ ((unused)),
			       const struct tr069_element *elem __attribute__ ((unused)),
			       DM_VALUE val)
{
	set_DM_UINT(val, monotonic_time());

	return val;
}

DM_VALUE get_IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining(const struct tr069_value_table *base __attribute__ ((unused)),
						       tr069_id id __attribute__ ((unused)),
						       const struct tr069_element *elem __attribute__ ((unused)),
						       DM_VALUE val)
{
	time_t now;

	now = monotonic_time();

	debug("(): now: %d, val: %d", (int)now, DM_INT(val));
	if (DM_INT(val) > now) {
		set_DM_INT(val, DM_INT(val) - now);
	} else
		set_DM_INT(val, 0);

	return val;
}

static void *tr069_ping_thread(void *arg __attribute__ ((unused)))
{
	struct tr069_value_table *ptab;

	struct addrinfo	*addrinfo, hint;

	const char	*host;
	unsigned int	send_cnt;
	unsigned int	timeout;

	unsigned int	*succ_cnt;
	unsigned int	*fail_cnt;
	unsigned int	*tavg;
	unsigned int	*tmin;
	unsigned int	*tmax;

	cwmp___IGD_PingDiag_DiagnosticsState_e state = cwmp___IGD_PingDiag_DiagnosticsState_None;

	ENTER();

	/** VAR: InternetGatewayDevice.IPPingDiagnostics */
	ptab = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							     cwmp__IGD_IPPingDiagnostics, 0});
	if (!ptab) {
		debug("(): couldn't get IPPingDiagnostics from storage\n");
		goto errout;
	}

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.Host */
	host = tr069_get_string_by_id(ptab, cwmp__IGD_PingDiag_Host);
	if (!host) {
		debug("(): Host unitialized\n");
		goto errout;
	}

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.NumberOfRepetitions */
	send_cnt = tr069_get_uint_by_id(ptab, cwmp__IGD_PingDiag_NumberOfRepetitions);
	if (!send_cnt) {
		debug("(): invalid value for NumberOfRepitions\n");
		goto errout;
	}

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.Timeout */
	timeout  = tr069_get_uint_by_id(ptab, cwmp__IGD_PingDiag_Timeout);
	if (!timeout) {
		debug("(): invalid value for Timeout\n");
		goto errout;
	}

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.SuccessCount */
	succ_cnt = tr069_get_uint_ref_by_id(ptab, cwmp__IGD_PingDiag_SuccessCount);

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.FailureCount */
	fail_cnt = tr069_get_uint_ref_by_id(ptab, cwmp__IGD_PingDiag_FailureCount);

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.AverageResponseTime */
	tavg = tr069_get_uint_ref_by_id(ptab, cwmp__IGD_PingDiag_AverageResponseTime);

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.MinimumResponseTime */
	tmin = tr069_get_uint_ref_by_id(ptab, cwmp__IGD_PingDiag_MinimumResponseTime);

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.MaximumResponseTime */
	tmax = tr069_get_uint_ref_by_id(ptab, cwmp__IGD_PingDiag_MaximumResponseTime);

	debug("(): host: %s, send: %u, timeout: %u\n", host, send_cnt, timeout);

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;

	if (getaddrinfo(host, NULL, &hint, &addrinfo)) {
		state = cwmp___IGD_PingDiag_DiagnosticsState_Error_CannotResolveHostName;
	} else {
		int r;

		r = tr069_ping(*(struct sockaddr_in*)addrinfo->ai_addr, send_cnt, timeout,
			       succ_cnt, fail_cnt, tavg, tmin, tmax, NULL, NULL);

		freeaddrinfo(addrinfo);

		if (!r)
			state = cwmp___IGD_PingDiag_DiagnosticsState_Complete;
	}

errout:

	pthread_mutex_lock(&ping_mutex);

	/** VAR: InternetGatewayDevice.IPPingDiagnostics.DiagnosticsState */
	tr069_set_enum_by_id(ptab, cwmp__IGD_PingDiag_DiagnosticsState, state);

	ping_running = 0;
	pthread_mutex_unlock(&ping_mutex);

	EXIT();
	return NULL;
}

static pthread_t ping_tid;

int set_IGD_PingDiag_DiagnosticsState(struct tr069_value_table *base __attribute__ ((unused)),
				      tr069_id id __attribute__ ((unused)),
				      const struct tr069_element *elem __attribute__ ((unused)),
				      DM_VALUE *st,
				      DM_VALUE val)
{
	set_DM_ENUM(*st, DM_ENUM(val));
	DM_parity_update(*st);

	ENTER();
	debug("(): val: %d, ping: %d\n", DM_ENUM(val), ping_running);
	if (DM_ENUM(val) == cwmp___IGD_PingDiag_DiagnosticsState_Requested &&
	    !ping_running) {
		pthread_mutex_lock(&ping_mutex);
		if (!ping_running) {
			pthread_create(&ping_tid, NULL, tr069_ping_thread, NULL);
			pthread_detach(ping_tid);
			ping_running = 1;
		}
		pthread_mutex_unlock(&ping_mutex);
	}
	EXIT();

	return 0;
}

static struct _tr069_trace_ctx {
	ev_async async;

	cwmp___IGD_TraceRDiagnostics_DiagnosticsState_e state;

	struct tr069_trace_stats {
		struct tr069_trace_hop {
			char		hostname[255+1];
			struct in_addr	ip;

			int		triptimes[3]; /* NumberOfTries is at most 3 */
			int		cTriptimes;
		} hops[64]; /* MaxHopCount is at most 64 */
		int lastHop;

		int tries;
	} *stats;
} tr069_trace_ctx;

static int tr069_trace_cb(void *ud, enum tr069_trace_state state, unsigned int hop,
			  const char *hostname, struct in_addr ip, int triptime)
{
	struct tr069_trace_stats *stats = ud;
	struct tr069_trace_hop *cur = stats->hops + hop - 1;

	ENTER();
	cur->triptimes[cur->cTriptimes++] = triptime;

	if (cur->cTriptimes == stats->tries || state > tr069_trace_error) {
		if (hostname)
			strncpy(cur->hostname, hostname, sizeof(cur->hostname));
		cur->ip = ip;

		stats->lastHop = hop;
	}

	EXIT();
	return 0;
}

static void *tr069_trace_thread(void *arg __attribute__ ((unused)))
{
	struct tr069_value_table *ttab;

	struct addrinfo	*addrinfo, hint;

	const char	*host;
	unsigned int	tries;
	unsigned int	timeout;
	unsigned int	blksize;
	unsigned int	mxhpcnt;

	ENTER();

	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics */
	ttab = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							     cwmp__IGD_TraceRouteDiagnostics, 0 });
	if (!ttab) {
		debug("(): couldn't get TraceRDiagnostics from storage\n");
		goto errout;
	}

	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.Host */
	host = tr069_get_string_by_id(ttab, cwmp__IGD_TraceRDiagnostics_Host);
	if (!host) {
		debug("(): Host unitialized\n");
		goto errout;
	}

	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.NumberOfTries */
	tries = tr069_get_uint_by_id(ttab, cwmp__IGD_TraceRDiagnostics_NumberOfTries);
	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.Timeout */
	timeout  = tr069_get_uint_by_id(ttab, cwmp__IGD_TraceRDiagnostics_Timeout);
	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.DataBlockSize */
	blksize = tr069_get_uint_by_id(ttab, cwmp__IGD_TraceRDiagnostics_DataBlockSize);
	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.MaxHopCount */
	mxhpcnt = tr069_get_uint_by_id(ttab, cwmp__IGD_TraceRDiagnostics_MaxHopCount);
	if (!tries || !timeout || !blksize || !mxhpcnt) {
		debug("(): invalid value for NumberOfTries, Timeout, DataBlockSize or MaxHopCount\n");
		goto errout;
	}

 	debug("(): host: %s, tries: %u, timeout: %u, blksize: %u, mxhpcnt: %u\n",
 	      host, tries, timeout, blksize, mxhpcnt);

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;

	if (getaddrinfo(host, NULL, &hint, &addrinfo)) {
		tr069_trace_ctx.state = cwmp___IGD_TraceRDiagnostics_DiagnosticsState_Error_CannotResolveHostName;
	} else {
		struct sockaddr_in *addr = (struct sockaddr_in*)addrinfo->ai_addr;

		addr->sin_port = htons(TRACEROUTE_STDPORT);

		if ((tr069_trace_ctx.stats = calloc(sizeof(struct tr069_trace_stats), 1))) {
			enum tr069_trace_state r;

			tr069_trace_ctx.stats->tries = tries;

			r = tr069_trace(*addr, tries, timeout, blksize, mxhpcnt,
					tr069_trace_cb, tr069_trace_ctx.stats);
			switch (r) {
			case tr069_trace_done:
				tr069_trace_ctx.state = cwmp___IGD_TraceRDiagnostics_DiagnosticsState_Complete;
				break;
			case tr069_trace_hop:
				tr069_trace_ctx.state = cwmp___IGD_TraceRDiagnostics_DiagnosticsState_Error_MaxHopCountExceeded;
			default:
				break;
			}
		}

		freeaddrinfo(addrinfo);
	}

errout:

	ev_async_send(EV_DEFAULT_ &tr069_trace_ctx.async);

	EXIT();
	return NULL;
}

static void tr069_trace_add_route_hops(EV_P_ ev_async *w,
				       int revents __attribute__((unused)))
{
	char buf[17];

	ENTER();

	if (!tr069_trace_ctx.stats)
		goto cleanup;

	for (struct tr069_trace_hop *cur = tr069_trace_ctx.stats->hops;
	     tr069_trace_ctx.stats->lastHop;
	     cur++, tr069_trace_ctx.stats->lastHop--) {
		struct tr069_instance_node *node;
		tr069_id id = TR069_ID_AUTO_OBJECT;

		/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops */
		node = tr069_add_instance_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
									cwmp__IGD_TraceRouteDiagnostics,
									cwmp__IGD_TraceRDiagnostics_RouteHops, 0 }, &id);
		if (!node || !inet_ntop(AF_INET, &cur->ip, buf, sizeof(buf))) {
			tr069_trace_ctx.state = cwmp___IGD_TraceRDiagnostics_DiagnosticsState_None;
			break;
		}

		if (*cur->hostname) {
			/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops.{i}.HopHost */
			tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_TraceRDiagnostics_RouteHops_i_HopHost, cur->hostname);

			/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops.{i}.HopHostAddress */
			tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_TraceRDiagnostics_RouteHops_i_HopHostAddress, buf);
		} else {
			/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops.{i}.HopHost */
			tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_TraceRDiagnostics_RouteHops_i_HopHost, buf);
		}

#if 0 /* our traceroute works more like a tracepath, so this field doesn't really make sense (leave it 0) */
		/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops.{i}.HopErrorCode */
		tr069_set_uint_by_id(DM_TABLE(node->table), cwmp__IGD_TraceRDiagnostics_RouteHops_i_HopErrorCode, 0);
#endif

		/* FIXME: this is quite inflexible, also it might be better to leave out -1 "triptimes" completely */
		switch (cur->cTriptimes) {
			case 1: snprintf(buf, sizeof(buf), "%d", cur->triptimes[0]); break;
			case 2: snprintf(buf, sizeof(buf), "%d,%d", cur->triptimes[0], cur->triptimes[1]); break;
			case 3: snprintf(buf, sizeof(buf), "%d,%d,%d", cur->triptimes[0], cur->triptimes[1], cur->triptimes[2]);
		}

		/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops.{i}.HopRTTimes */
		tr069_set_string_by_id(DM_TABLE(node->table), cwmp__IGD_TraceRDiagnostics_RouteHops_i_HopRTTimes, buf);
	}

	free(tr069_trace_ctx.stats);

cleanup:

	ev_async_stop(EV_A_ w);

	pthread_mutex_lock(&trace_mutex);

	/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.DiagnosticsState */
	tr069_set_enum_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
						     cwmp__IGD_TraceRouteDiagnostics,
						     cwmp__IGD_TraceRDiagnostics_DiagnosticsState, 0 },
				   tr069_trace_ctx.state, DV_UPDATED);

	trace_running = 0;
	pthread_mutex_unlock(&trace_mutex);

	EXIT();
}

static pthread_t trace_tid;

int set_IGD_TraceRDiagnostics_DiagnosticsState(struct tr069_value_table *base __attribute__ ((unused)),
					       tr069_id id __attribute__ ((unused)),
					       const struct tr069_element *elem __attribute__ ((unused)),
					       DM_VALUE *st,
					       DM_VALUE val)
{
	set_DM_ENUM(*st, DM_ENUM(val));
	DM_parity_update(*st);

	ENTER();
	debug("(): val: %d, trace: %d\n", DM_ENUM(val), trace_running);
	if (DM_ENUM(val) == cwmp___IGD_TraceRDiagnostics_DiagnosticsState_Requested &&
	    !trace_running) {
		pthread_mutex_lock(&trace_mutex);
		if (!trace_running) {
			/** VAR: InternetGatewayDevice.TraceRouteDiagnostics.RouteHops */
			tr069_del_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								      cwmp__IGD_TraceRouteDiagnostics,
								      cwmp__IGD_TraceRDiagnostics_RouteHops, 0 });

			memset(&tr069_trace_ctx, 0, sizeof(struct _tr069_trace_ctx));
			ev_async_init(&tr069_trace_ctx.async, tr069_trace_add_route_hops);
			ev_async_start(EV_DEFAULT_ &tr069_trace_ctx.async);

			pthread_create(&trace_tid, NULL, tr069_trace_thread, NULL);
			pthread_detach(trace_tid);
			trace_running = 1;
		}
		pthread_mutex_unlock(&trace_mutex);
	}
	EXIT();

	return 0;
}

static int		pcap_running = 0;
static pthread_mutex_t	pcap_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *tr069_pcap_thread(void *arg __attribute__ ((unused)))
{
	struct ev_loop *cap_loop;
	struct tr069_value_table *pctab;

	tr069_selector *ifacesel;
	static const char *dmpfile = "/tmp/dump.cap";
	const char *interface, *t_dumpurl;
	char *dumpurl = NULL, *hostname, *path;
	int pr, port;
	unsigned int timeout, maxbytes, maxpackages;

	cwmp___IGD_X_TPLINO_NET_PCapDump_State_e state;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump */
	pctab = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							      cwmp__IGD_X_TPLINO_NET_PCapDump, 0});
	if (!pctab) {
		debug("(): couldn't get PCapDump from storage\n");
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_PCAP;
		goto errout;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump.Interface */
	ifacesel = tr069_get_selector_by_id(pctab,  cwmp__IGD_X_TPLINO_NET_PCapDump_Interface);
	if (!ifacesel ||
	    !(interface = get_if_device(*ifacesel))) {
		debug("(): invalid value for Interface\n");
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_PCAP;
		goto errout;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump.UploadURL */
	t_dumpurl = tr069_get_string_by_id(pctab, cwmp__IGD_X_TPLINO_NET_PCapDump_UploadURL);
	if (!t_dumpurl) {
		debug("(): UploadURL unitialized\n");
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_TFTP;
		goto errout;
	}
	if (!(dumpurl = strdup(t_dumpurl))) {
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_TFTP;
		goto errout;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump.Timeout */
	timeout = tr069_get_uint_by_id(pctab, cwmp__IGD_X_TPLINO_NET_PCapDump_Timeout);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump.MaxKBytes */
	maxbytes = tr069_get_uint_by_id(pctab, cwmp__IGD_X_TPLINO_NET_PCapDump_MaxKBytes);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump.MaxPackages */
	maxpackages = tr069_get_uint_by_id(pctab, cwmp__IGD_X_TPLINO_NET_PCapDump_MaxPackages);
	if (!timeout || !maxbytes || !maxpackages) {
		debug("(): invalid value for Timeout, MaxKBytes or MaxPackages\n");
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_PCAP;
		goto errout;
	}

	if ((pr = parse_tftp_url(dumpurl, &hostname, &path, &port)) < DEFAULTFILE) {
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_TFTP;
		goto errout;
	}

	debug("(): Capturing %u milliseconds from %s, trying to get %u Kbytes or %u packages, either.",
	      timeout, interface, maxbytes, maxpackages);
	debug("(): TFTP: Path = %s | Port = %s ", path, hostname);

	if (initcap(interface, timeout, maxbytes, maxpackages) < 0) {
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_PCAP;
		goto errout;
	}

	if ((cap_loop = ev_loop_new(0)) == NULL) {
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_PCAP;
		goto errout;
	}

	cap_start_watchers(cap_loop);
	ev_loop(cap_loop, 0);
	cap_rem_watchers(cap_loop);
	ev_loop_destroy(cap_loop);

	cleancap();

	/*
	 * NOTE: parse_tftp_url() does not permit any character in "hostname" or "path"
	 * that may be used to exploit the shell. It does permit spaces in "path"
	 * though.
	 */
	if (vasystem("tftp -p -l %s -r \"%s%s\" \"%s\" %d",
		     dmpfile,
		     path, pr == DEFAULTFILE ? dmpfile + 5 : "",
		     hostname, port)) {
		unlink(dmpfile);
		state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Error_TFTP;
		goto errout;
	}
	unlink(dmpfile);

	state = cwmp___IGD_X_TPLINO_NET_PCapDump_State_Complete;

errout:

	free(dumpurl);

	pthread_mutex_lock(&pcap_mutex);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_PCapDump.State */
	tr069_set_enum_by_id(pctab, cwmp__IGD_X_TPLINO_NET_PCapDump_State, state);

	pcap_running = 0;
	pthread_mutex_unlock(&pcap_mutex);

	EXIT();
	return NULL;
}

static pthread_t pcap_tid;

int set_IGD_X_TPLINO_NET_PCapDump_State(struct tr069_value_table *base __attribute__ ((unused)),
					       tr069_id id __attribute__ ((unused)),
					       const struct tr069_element *elem __attribute__ ((unused)),
					       DM_VALUE *st,
					       DM_VALUE val)
{
	set_DM_ENUM(*st, DM_ENUM(val));
	DM_parity_update(*st);

	ENTER();
	debug("(): val: %d, pcap: %d\n", DM_ENUM(val), pcap_running);
	if (DM_ENUM(val) == cwmp___IGD_X_TPLINO_NET_PCapDump_State_Requested &&
	    !pcap_running) {
		pthread_mutex_lock(&pcap_mutex);
		if (!pcap_running) {
			pthread_create(&pcap_tid, NULL, tr069_pcap_thread, NULL);
			pthread_detach(pcap_tid);
			pcap_running = 1;
		}
		pthread_mutex_unlock(&pcap_mutex);
	}
	EXIT();

	return 0;
}

static int dnschange = 0;

int set_IGD_X_TPLINO_NET_DNSResolver_DNSServer(struct tr069_value_table *base __attribute__ ((unused)),
						tr069_id id __attribute__ ((unused)),
						const struct tr069_element *elem __attribute__ ((unused)),
						DM_VALUE *st,
						DM_VALUE val)
{
	ENTER();

	if (st == NULL || memcmp(DM_IP4_REF(*st), DM_IP4_REF(val), sizeof(struct in_addr))) {
		dnschange = 1;
		debug("(): DNS Changed.");
	} else
		dnschange = 0;

	set_DM_IP4(*st, DM_IP4(val));

	EXIT();

	return 0;
}

int set_IGD_X_TPLINO_NET_DNSResolver_State(struct tr069_value_table *base __attribute__ ((unused)),
					    tr069_id id __attribute__ ((unused)),
					    const struct tr069_element *elem __attribute__ ((unused)),
					    DM_VALUE *st,
					    DM_VALUE val)
{
	struct tr069_value_table *rtab;
	cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_e dir;
	const char *hostname;
	const struct in_addr *ipaddr, *dnsserver;

	ENTER();

	debug("(): st: %i, val: %i\n", DM_ENUM(*st), DM_ENUM(val));

	if (DM_ENUM(val) != cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Requested ||
	    DM_ENUM(*st) == cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Requested)
		goto res_errout;

	set_DM_ENUM(*st, DM_ENUM(val));
	DM_parity_update(*st);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_DNSResolver */
	if ((rtab = tr069_get_table_by_selector((tr069_selector) {cwmp__InternetGatewayDevice, cwmp__IGD_X_TPLINO_NET_DNSResolver, 0})) == NULL) {
		debug("(): couldn't get DNSResolver from storage\n");
		goto res_errout;
	}

	if (eva_usage >= 0 && dnschange) {
		debug("(): DNSServer changed while resolving engine was active!\n");
		goto res_dnsbug;
	}

	dnsserver = tr069_get_ipv4_ref_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_DNSServer);
	if (dnsserver != NULL)
		debug("(): DNSResolver %s specified\n", inet_ntoa(*dnsserver));

	tr069d_evdns_init(dnsserver);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_DNSResolver.Direction */
	dir = tr069_get_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_Direction);
	switch (dir) {
		case cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Normal:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_DNSResolver.HostName */
			if ((hostname = tr069_get_string_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_HostName)) == NULL) {
				debug("(): Host unitialized\n");
				goto res_errout;
			}
			debug("(): Now resolving %s\n", hostname);
			ares_gethostbyname(dns_channel, hostname, AF_INET, async_resolve, NULL);
			break;
		case cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Reverse:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_DNSResolver.IP */
			if ((ipaddr = tr069_get_ipv4_ref_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_IP)) == NULL) {
				debug("(): No IP given\n");
				goto res_errout;
			}
			debug("(): Now resolving %s\n", inet_ntoa(*ipaddr));
			ares_gethostbyaddr(dns_channel, ipaddr, sizeof(struct in_addr), AF_INET, async_resolve, NULL);
			break;
		case cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Not_Configured:
		default:
			debug("(): DNSResolver direction misconfigured\n");
			goto res_errout;
	}

	goto res_clean;

res_errout:
	tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_State, cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Error);
	goto res_clean;

res_dnsbug:
	tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_State, cwmp___IGD_X_TPLINO_NET_DNSResolver_State_DNSChange);

res_clean:
	EXIT();
	return 0;
}

int set_IGD_MgtSrv_X_TPBS_BootstrapState(struct tr069_value_table *base __attribute__ ((unused)),
					 tr069_id id __attribute__ ((unused)),
					 const struct tr069_element *elem __attribute__ ((unused)),
					 DM_VALUE *st,
					 DM_VALUE val)
{
	ENTER();

	set_DM_ENUM(*st, DM_ENUM(val));
	DM_parity_update(*st);

	if (DM_ENUM(val) == cwmp___IGD_MgtSrv_X_TPBS_BootstrapState_None) {
		tr069_clear_event_by_type(EV_CPE_BOOTSTRAP);
	} else if (DM_ENUM(val) == cwmp___IGD_MgtSrv_X_TPBS_BootstrapState_Requested) {
		doBootstrap();
	}

	EXIT();
	return 0;
}

int set_IGD_CfgSeg_ConfigPassword(struct tr069_value_table *base __attribute__ ((unused)),
				  tr069_id id __attribute__ ((unused)),
				  const struct tr069_element *elem __attribute__ ((unused)),
				  DM_VALUE *st,
				  DM_VALUE val)
{
	DM_RESULT r;

	ENTER();

	tr069_set_string_value(st, DM_STRING(val));

	lua_pushstring(lua_environment, DM_STRING(val) ? : "");
	r = fp_Lua_function("fncAdminPasswd", 1);

	EXIT();
	return (int)r;
}

DM_VALUE get_IGD_Time_CurrentLocalTime(const struct tr069_value_table *base __attribute__ ((unused)),
				       tr069_id id __attribute__ ((unused)),
				       const struct tr069_element *elem __attribute__ ((unused)),
				       DM_VALUE val)
{
	ENTER();

	set_DM_TIME(val, time(NULL));

	EXIT();
	return val;
}

int set_IGD_Time_LocalTimeZoneName(struct tr069_value_table *base __attribute__ ((unused)),
				  tr069_id id __attribute__ ((unused)),
				  const struct tr069_element *elem __attribute__ ((unused)),
				  DM_VALUE *st,
				  DM_VALUE val)
{
	FILE *fout;

	ENTER();

	tr069_set_string_value(st, DM_STRING(val));

	fout = fopen(TZ_FILE, "w");
	if (fout) {
		fprintf(fout, "%s\n", DM_STRING(val) ? DM_STRING(val) : "");
		fclose(fout);
	}

	EXIT();
	return !fout;
}

static unsigned int getUIntStatfromSys(const tr069_selector sel, const char *stats)
{
	FILE *fin;
	char buffer[64];
	char *end;
	long int l = 0;
	const char *dev = NULL;

	ENTER();

	dev = get_if_device(sel);

	debug(": got device: %s", dev ? dev : "(NULL)");

	snprintf(buffer, sizeof(buffer), "/sys/class/net/%s/statistics/%s", dev, stats);
	debug(": Trying to open %s", buffer);
	fin = fopen(buffer, "r");
	if (fin) {
		fgets(buffer, sizeof(buffer), fin);
		errno = 0;
		l = strtol(buffer, &end, 10);
		if (*end != 0x0A || errno != 0 || l < 0)
			l = 0;
		fclose(fin);
	}

	EXIT();

	return (unsigned int)l;
}

DM_VALUE get_IGD_LANDev_i_EthCfg_j_Stats_BytesSent(const struct tr069_value_table *base,
						   tr069_id id __attribute__ ((unused)),
						   const struct tr069_element *elem __attribute__ ((unused)),
						   DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2]};

	set_DM_UINT(val, getUIntStatfromSys(s, "tx_bytes"));
	return val;
}

DM_VALUE get_IGD_LANDev_i_EthCfg_j_Stats_BytesReceived(const struct tr069_value_table *base,
						       tr069_id id __attribute__ ((unused)),
						       const struct tr069_element *elem __attribute__ ((unused)),
						       DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2]};

	set_DM_UINT(val, getUIntStatfromSys(s, "rx_bytes"));
	return val;
}

DM_VALUE get_IGD_LANDev_i_EthCfg_j_Stats_PacketsSent(const struct tr069_value_table *base,
						     tr069_id id __attribute__ ((unused)),
						     const struct tr069_element *elem __attribute__ ((unused)),
						     DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2]};

	set_DM_UINT(val, getUIntStatfromSys(s, "tx_packets"));
	return val;
}

DM_VALUE get_IGD_LANDev_i_EthCfg_j_Stats_PacketsReceived(const struct tr069_value_table *base,
							 tr069_id id __attribute__ ((unused)),
							 const struct tr069_element *elem __attribute__ ((unused)),
							 DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2]};

	set_DM_UINT(val, getUIntStatfromSys(s, "rx_packets"));
	return val;
}

DM_VALUE get_IGD_WANDev_i_EthCfg_Stats_BytesSent(const struct tr069_value_table *base,
						 tr069_id id __attribute__ ((unused)),
						 const struct tr069_element *elem __attribute__ ((unused)),
						 DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2],
		 	    cwmp__IGD_WANDev_i_WANConnectionDevice, 1};

	set_DM_UINT(val, getUIntStatfromSys(s, "tx_bytes"));
	return val;
}

DM_VALUE get_IGD_WANDev_i_EthCfg_Stats_BytesReceived(const struct tr069_value_table *base,
						     tr069_id id __attribute__ ((unused)),
						     const struct tr069_element *elem __attribute__ ((unused)),
						     DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2],
		 	    cwmp__IGD_WANDev_i_WANConnectionDevice, 1};

	set_DM_UINT(val, getUIntStatfromSys(s, "rx_bytes"));
	return val;
}

DM_VALUE get_IGD_WANDev_i_EthCfg_Stats_PacketsSent(const struct tr069_value_table *base,
						   tr069_id id __attribute__ ((unused)),
						   const struct tr069_element *elem __attribute__ ((unused)),
						   DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2],
		 	    cwmp__IGD_WANDev_i_WANConnectionDevice, 1};

	set_DM_UINT(val, getUIntStatfromSys(s, "tx_packets"));
	return val;
}

DM_VALUE get_IGD_WANDev_i_EthCfg_Stats_PacketsReceived(const struct tr069_value_table *base,
						       tr069_id id __attribute__ ((unused)),
						       const struct tr069_element *elem __attribute__ ((unused)),
						       DM_VALUE val)
{
	tr069_selector s = {base->id[0], base->id[1], base->id[2],
		 	    cwmp__IGD_WANDev_i_WANConnectionDevice, 1};

	set_DM_UINT(val, getUIntStatfromSys(s, "rx_packets"));
	return val;
}
