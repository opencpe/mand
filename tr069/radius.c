/* */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>

#if defined (HAVE_LIBTOMCRYPT)
#include <tomcrypt.h>
#elif defined (HAVE_LIBPOLARSSL)
#include <polarssl/havege.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/aes.h>
#endif

#include <ev.h>

#include "radlib.h"
#include "radlib_vs.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_action.h"
#include "tr069_cfgsessions.h"

#define SDEBUG
#include "dm_assert.h"
#include "debug.h"
#include "radius.h"
#include "ifup.h"
#include "client.h"
#include "monitor.h"

#ifndef MAXBLOCKSIZE
#define MAXBLOCKSIZE  128
#endif

#define AES_BLOCK_LEN 16

static int auth_srvfd = -1;
static int acct_srvfd = -1;
	 
static ev_io auth_srvev;
static ev_io acct_srvev;

#if defined (HAVE_LIBTOMCRYPT)
static int hash_idx;
static int cipher_idx;
#elif defined (HAVE_LIBPOLARSSL)
havege_state h_state;
#endif

static void authsrv_ev_cb(EV_P_ ev_io *w, int revents);
static void acctsrv_ev_cb(EV_P_ ev_io *w, int revents);

static void auth_notify_cb(int, struct rad_handle *, void *, void *);
static void acct_notify_cb(int, struct rad_handle *, void *, void *);

static void update_scg_radius_server(struct tr069_value_table *server)
{
	int port;
	int timeout;
	int maxtries;
	int type;
	struct in_addr host;
	const char *secret;
	struct rad_server *srv;

	ENTER();

	/* FIXME: these values need to go into the configuration */
	timeout = 8;
	maxtries = 3;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.RadiusSecret */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.RadiusSecret */
	secret = tr069_get_string_by_id(server, cwmp__IGD_SCG_RC_Auth_Srv_i_RadiusSecret);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.IP */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.IP */
	host = tr069_get_ipv4_by_id(server, cwmp__IGD_SCG_RC_Auth_Srv_i_IP);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Port */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Port */
	port = tr069_get_uint_by_id(server, cwmp__IGD_SCG_RC_Auth_Srv_i_Port);

	type = server->id[3] == cwmp__IGD_SCG_RS_Authentication ? RADIUS_AUTH : RADIUS_ACCT;

	if (host.s_addr == INADDR_ANY || host.s_addr == INADDR_NONE || !secret)
		return;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.X_DM_RadiusServerStruct */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.X_DM_RadiusServerStruct */
	srv = tr069_get_ptr_by_id(server, cwmp__IGD_SCG_RC_Auth_Srv_i_X_DM_RadiusServerStruct);
	debug(": rad_server: %p", srv);
	if (srv) {
		rad_update_server(srv, type, host, port, secret, timeout, maxtries);
	} else {
		srv = rad_new_server(type, host, port, secret, timeout, maxtries);
		if (srv)
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.X_DM_RadiusServerStruct */
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.X_DM_RadiusServerStruct */
			tr069_set_ptr_by_id(server, cwmp__IGD_SCG_RC_Auth_Srv_i_X_DM_RadiusServerStruct, srv);
	}

	EXIT_MSG(": rad_server: %p", srv);
}

static int init_radius_server(EV_P_ ev_io *w, void (*cb)(EV_P_ struct ev_io *, int), int type, int port)
{
	int sk, rc;
	int opt = 1;
	int mtu = IP_PMTUDISC_DONT;

	ENTER(" type: %d, port: %d", type, port);

	sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk > 0) {
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_port = htons(port),
			.sin_addr.s_addr = INADDR_ANY,
		};

		fcntl(sk, F_SETFD, FD_CLOEXEC | fcntl(sk, F_GETFD));
		fcntl(sk, F_SETFL, O_NONBLOCK);

		setsockopt(sk, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
		setsockopt(sk, SOL_IP, IP_PKTINFO, &opt, sizeof(opt));
		setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		rc = bind(sk, &sin, sizeof(sin));
		if (rc < 0) {
			debug(": rc: %d (%m)", rc);
			close(sk);
			EXIT();
			return -1;
		}

		w->data = (void *)type;
		ev_io_init(w, cb, sk, EV_READ);
		ev_io_start(EV_A_ w);
	}

	debug(": sk: %d", sk);
	EXIT();

	return sk;
}

static void init_scg_radius(void)
{
	struct tr069_instance *auth_rs;
	struct tr069_instance *acct_rs;
	struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server */
	auth_rs = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_RadiusClient,
				cwmp__IGD_SCG_RC_Authentication,
				cwmp__IGD_SCG_RC_Auth_Server, 0});

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server */
	acct_rs = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_RadiusClient,
				cwmp__IGD_SCG_RC_Accounting,
				cwmp__IGD_SCG_RC_Acct_Server, 0});

	if (!auth_rs && !auth_rs) {
		EXIT();
		return;
	}

	/* init the radlib */
	rad_init();

#if defined (HAVE_LIBTOMCRYPT)
	/* register AES first */
	if ((cipher_idx = register_cipher(&aes_desc)) == -1) {
		debug("Error registering cipher.");
		return;
	}

	hash_idx = find_hash("sha1");
	if (hash_idx == -1) {
		debug("Error getting hash.");
		return;
	}
	if (cipher_idx == -1) {
		debug("Error getting cipher.");
		return;
	}
#elif defined (HAVE_LIBPOLARSSL)
	havege_init(&h_state);
#endif

	if (auth_rs)
		for (node = tr069_instance_first(auth_rs);
		     node != NULL;
		     node = tr069_instance_next(auth_rs, node))
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i} */
			update_scg_radius_server(DM_TABLE(node->table));

	if (acct_rs)
		for (node = tr069_instance_first(acct_rs);
		     node != NULL;
		     node = tr069_instance_next(acct_rs, node))
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i} */
			update_scg_radius_server(DM_TABLE(node->table));

	auth_srvfd = init_radius_server(EV_DEFAULT_ &auth_srvev, authsrv_ev_cb, RADIUS_AUTH, 1812);
	acct_srvfd = init_radius_server(EV_DEFAULT_ &acct_srvev, acctsrv_ev_cb, RADIUS_AUTH, 1813);

	EXIT();
}

static struct tr069_value_table *get_radius_client(struct tr069_value_table *znt, const struct in_addr from, int type)
{
	struct tr069_value_table *radius;
	struct tr069_instance *i;
	struct tr069_instance_node *node;
	tr069_id clnt_id;
#if defined(SDEBUG)
        char b1[128];
#endif

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius */
	radius = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Radius);
	if (!radius) {
		EXIT();
		return NULL;
	}

	switch (type) {
	case RADIUS_AUTH:
		i = tr069_get_instance_ref_by_id(radius, cwmp__IGD_SCG_Zone_i_Radius_AuthClient);
		clnt_id = cwmp__IGD_SCG_Zone_i_Radius_AuthClient_j_Client;
		break;

	case RADIUS_ACCT:
		i = tr069_get_instance_ref_by_id(radius, cwmp__IGD_SCG_Zone_i_Radius_AcctClient);
		clnt_id = cwmp__IGD_SCG_Zone_i_Radius_AcctClient_j_Client;
		break;

	default:
		EXIT();
		return NULL;
	}

	if (!i) {
		EXIT();
		return NULL;
	}

	for (node = tr069_instance_first(i);
	     node != NULL;
	     node = tr069_instance_next(i, node)) {
		tr069_selector *clntsel;
		struct tr069_value_table *clnt;
		int plen;
		struct in_addr prefix;
		struct in_addr mask;

		debug("(): instance: %s\n", sel2str(b1, DM_TABLE(node->table)->id));

		clntsel = tr069_get_selector_by_id(DM_TABLE(node->table), clnt_id);
		if (!clntsel)
			continue;

		debug("(): client sel: %s\n", sel2str(b1, *clntsel));
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client */
		clnt = tr069_get_table_by_selector(*clntsel);
		if (!clnt)
			continue;
		debug("(): client: %s\n", sel2str(b1, clnt->id));

		if ((*clntsel)[3] == cwmp__IGD_SCG_RS_Authentication) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Prefix */
			prefix = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_RS_Auth_Clnt_i_Prefix);

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.PrefixLen */
			plen = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_RS_Auth_Clnt_i_PrefixLen);
		} else {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client.{i}.Prefix */
			prefix = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_RS_Acct_Clnt_i_Prefix);

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client.{i}.PrefixLen */
			plen = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_RS_Acct_Clnt_i_PrefixLen);
		}
		debug("(): prefix: %d, mask: %08x\n", plen, 0xFFFFFFFF << (32 - plen));

		if (plen < 32)
			mask.s_addr = htonl(0xFFFFFFFF << (32 - plen));
		else
			mask.s_addr = 0xFFFFFFFF;

		debug("(): compare %08x ... %08x", ntohl(prefix.s_addr & mask.s_addr), ntohl(from.s_addr & mask.s_addr));
		if ((from.s_addr & mask.s_addr) == (prefix.s_addr & mask.s_addr)) {
			EXIT();
			return clnt;
		}
	}

	EXIT();
	return NULL;
}

static void update_session_from_radius(struct tr069_value_table *znt, struct rad_packet *req)
{
	const void *data;
	size_t len;
	int attr;

#define GOT_FRAMED_IP      (1 >> 0)
#define GOT_CALLING_MAC    (1 >> 1)
#define GOT_CALLED_STATION (1 >> 2)
#define GOT_LOCATION_ID    (1 >> 3)
	int flags = 0;

	const struct in_addr *framed_ip = NULL;
	const uint8_t *calledstationid = NULL; size_t calledstationid_len = 0;
	char *user = NULL;
	char *locationid = NULL;
	char *relsessid = NULL;
	char macbuf[18];
	char *mac = NULL;
	unsigned int keep_alive_timeout = UINT_MAX;
	int acct_status_type = -1;
	int acct_term_cause = RAD_TERM_NAS_REQUEST;

	ENTER();

	while ((attr = rad_get_attr(req, &data, &len)) > 0) {
		if (attr == RAD_VENDOR_SPECIFIC) {
			uint32_t vendor;

			attr = rad_get_vendor_attr(&vendor, &data, &len);
			debug("(): vendor: %d, attr: %d, len: %d", vendor, attr, (int)len);

			switch (vendor) {
			case RAD_VENDOR_TRAVELPING:
				switch (attr) {
				case RAD_TRAVELPING_LOCATION_ID:
					locationid = strndup(data, len);
					flags |= GOT_LOCATION_ID;
					break;

				case RAD_TRAVELPING_KEEP_ALIVE_TIMEOUT:
					keep_alive_timeout = rad_cvt_int(data);
					break;

				default:
					break;
				}
			default:
				break;
			}
		} else {
			debug("(): attr: %d, len: %d", attr, (int)len);

			switch (attr) {
			case  RAD_ACCT_STATUS_TYPE:
				acct_status_type = rad_cvt_int(data);
				break;

			case RAD_ACCT_TERMINATE_CAUSE:
				acct_term_cause = rad_cvt_int(data);
				break;

			case RAD_ACCT_SESSION_ID:
				relsessid = strndup(data, len);
				break;

			case RAD_FRAMED_IP_ADDRESS:
				if (len != 4)
					break;

				framed_ip = (struct in_addr *)data;
				flags |= GOT_FRAMED_IP;
				break;

			case RAD_CALLING_STATION_ID: {
				uint8_t calling_mac[6];

				if (len < 17) {
					user = strndup(data, len);
					break;
				}

				if ((sscanf(data, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
					    &calling_mac[0], &calling_mac[1], &calling_mac[2],
					    &calling_mac[3], &calling_mac[4], &calling_mac[5]) != 6) &&
				    (sscanf(data, "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
					    &calling_mac[0], &calling_mac[1], &calling_mac[2],
					    &calling_mac[3], &calling_mac[4], &calling_mac[5]) != 6)) {
					user = strndup(data, len);
					break;
				}

				snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
					 calling_mac[0], calling_mac[1], calling_mac[2],
					 calling_mac[3], calling_mac[4], calling_mac[5]);
				mac = macbuf;

				flags |= GOT_CALLING_MAC;
				break;
			}

			case RAD_CALLED_STATION_ID:
				calledstationid = data;
				calledstationid_len = len;
				flags |= GOT_CALLED_STATION;

			default:
				break;
			}
		}
	}

	switch (acct_status_type) {
	case RAD_START:
	case RAD_UPDATE:
		if ((flags & (GOT_FRAMED_IP | GOT_CALLED_STATION)) == (GOT_FRAMED_IP | GOT_CALLED_STATION)) {
			hs_update_client_called_station(znt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddressSource_Radius,
							*framed_ip, mac, user,
							calledstationid, calledstationid_len,
							(const uint8_t *)locationid, (const uint8_t *)relsessid,
							keep_alive_timeout);
		}
		break;

	case RAD_STOP:
		if (flags & GOT_FRAMED_IP)
			hs_remove_client_by_zone(znt, *framed_ip, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_User_Request);
		break;
	}

	free(user);
	free(locationid);
	free(relsessid);
	rad_get_reset(req);
	EXIT();
}

static struct rad_packet *rad_auth_req(struct tr069_value_table *znt __attribute__ ((unused)),
				       struct tr069_value_table *clnt, struct rad_packet *req)
{
	struct tr069_value_table *globs;
	struct tr069_value_table *stats;
	struct rad_packet *resp = NULL;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Stats */
	globs = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_RadiusServer,
				cwmp__IGD_SCG_RS_Authentication,
				cwmp__IGD_SCG_RS_Auth_Stats, 0});

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Stats */
	stats = tr069_get_table_by_id(clnt, cwmp__IGD_SCG_RS_Auth_Clnt_i_Stats);

	switch (rad_get_code(req)) {
	case RAD_ACCESS_REQUEST:
		debug("(): Access-Request");
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Stats.AccessRequests */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Auth_Stats_AccessRequests);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Stats.AccessRequests */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Auth_Clnt_i_Stats_AccessRequests);

		resp = rad_init_response(req, RAD_ACCESS_REJECT);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Stats.AccessRejects */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Auth_Stats_AccessRejects);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Stats.AccessRejects */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Auth_Clnt_i_Stats_AccessRejects);

		break;

	case RAD_ACCESS_CHALLENGE:
		debug("(): Access-Challenge");
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Stats.AccessChallenges */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Auth_Stats_AccessChallenges);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Stats.AccessChallenges */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Auth_Clnt_i_Stats_AccessChallenges);

		resp = rad_init_response(req, RAD_ACCESS_REJECT);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Stats.AccessRejects */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Auth_Stats_AccessRejects);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Stats.AccessRejects */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Auth_Clnt_i_Stats_AccessRejects);

		break;

	default:
		debug("(): Radius-Request %d, ignoring", rad_get_code(req));
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Stats.UnknownTypes */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Auth_Stats_UnknownTypes);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client.{i}.Stats.UnknownTypes */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Auth_Clnt_i_Stats_UnknownTypes);

		break;
	}

	EXIT();
	return resp;
}

static struct rad_packet *rad_acct_req(struct tr069_value_table *znt,
				       struct tr069_value_table *clnt, struct rad_packet *req)
{
	struct tr069_value_table *stats;
	struct tr069_value_table *globs;
	struct rad_packet *resp = NULL;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Stats */
	globs = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_RadiusServer,
				cwmp__IGD_SCG_RS_Accounting,
				cwmp__IGD_SCG_RS_Acct_Stats, 0});

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client.{i}.Stats */
	stats = tr069_get_table_by_id(clnt, cwmp__IGD_SCG_RS_Acct_Clnt_i_Stats);

	switch (rad_get_code(req)) {
	case RAD_ACCOUNTING_REQUEST:
		debug("(): Accounting-Request");

		update_session_from_radius(znt, req);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Stats.Requests */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Acct_Stats_Requests);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client.{i}.Stats.Requests */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Acct_Clnt_i_Stats_Requests);

		resp = rad_init_response(req, RAD_ACCOUNTING_RESPONSE);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Stats.Responses */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Acct_Stats_Responses);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client.{i}.Stats.Responses */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Acct_Clnt_i_Stats_Responses);

		break;

	default:
		debug("(): Radius-Request %d, ignoring", rad_get_code(req));
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Stats.UnknownTypes */
		tr069_incr_uint_by_id(globs, cwmp__IGD_SCG_RS_Acct_Stats_UnknownTypes);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client.{i}.Stats.UnknownTypes */
		tr069_incr_uint_by_id(stats, cwmp__IGD_SCG_RS_Acct_Clnt_i_Stats_UnknownTypes);

		break;
	}

	EXIT();
	return resp;
}

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
}

static void authsrv_ev_cb(EV_P __attribute__((unused)), ev_io *w, int revents)
{
#if defined(SDEBUG)
	char ip[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
#endif

	struct tr069_instance *devi;
	struct tr069_instance_node *dev;
	tr069_selector *dref;
	struct tr069_value_table *znt;
	struct tr069_value_table *clnt;
	int type;
	const char *secret;
	struct rad_packet *req;
	struct rad_packet *resp = NULL;
	uint8_t packet[4096];
	struct iovec iov = {
		.iov_base = packet,
		.iov_len  = sizeof(packet),
	};

	struct in_addr laddr = { .s_addr = INADDR_ANY };
	struct sockaddr_in from;
	int if_idx = -1;
	static struct ifreq ifr = {
		.ifr_ifindex = -1,
	};
	ssize_t r;

	char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct cmsghdr *cmsg;

	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),

		.msg_iov = &iov,
		.msg_iovlen = 1,

		.msg_controllen = sizeof(cbuf),
		.msg_control    = &cbuf,
		.msg_flags = 0,
	};

	const void *data;
	size_t len;
	int attr;

	ENTER();

	if (!(revents & EV_READ)) {
		EXIT();
		return;
	}

	r = recvmsg(w->fd, &msg, MSG_DONTWAIT);
	if (r < 0) {
		debug("(): fd: %d, got error: %d, (%m)", w->fd, errno);
		EXIT();
		return;
	}
	debug("(): fd: %d, got r: %d", w->fd, (int)r);

	debug(": rc: %d", (int)r);
	debug(": msg_name: %s", ip2str(from.sin_addr, ip));
	debug(": iov_len: %d", (int)iov.iov_len);
	debug(": msg_controllen: %d", (int)msg.msg_controllen);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		debug(": cmsg: level: %d, type: %d", cmsg->cmsg_level, cmsg->cmsg_type);

		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pktinfo;

			pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			if_idx = pktinfo->ipi_ifindex;
			laddr = pktinfo->ipi_spec_dst;
			debug(": pktinfo: ifindex: %d, addr: %s, spec_dst: %s",
			      pktinfo->ipi_ifindex, ip2str(pktinfo->ipi_addr, ip), ip2str(pktinfo->ipi_spec_dst, dst));

		}
	}
	debug(": msg_flags: %x", msg.msg_flags);

	if (if_idx < 0) {
		EXIT();
		return;
	}
	if (ifr.ifr_ifindex != if_idx) {
		ifr.ifr_ifindex = if_idx;
		if (ioctl(w->fd, SIOCGIFNAME, &ifr) < 0) {
			EXIT();
			return;
		}
	}
	debug(": ifr_name: %s", ifr.ifr_name);

	devi = get_if_layout(ifr.ifr_name);
	if (!devi) {
		EXIT();
		return;
	}

	dev = tr069_instance_first(devi);
	if (!dev) {
		EXIT();
		return;
	}
	dref = tr069_get_selector_by_id(DM_TABLE(dev->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
	if (!dref) {
		EXIT();
		return;
	}

	req = rad_new_request(packet, r);
	if (!req) {
		EXIT();
		return;
	}

	znt = hs_get_zone_by_device(*dref);
	if (!znt) {
		/* scan the radius packet for a Zone Id */

		char zoneid[256];
		zoneid[0] = '\0';
		while ((attr = rad_get_attr(req, &data, &len)) > 0) {
			if (attr == RAD_VENDOR_SPECIFIC) {
				uint32_t vendor;

				attr = rad_get_vendor_attr(&vendor, &data, &len);
				if (vendor == RAD_VENDOR_TRAVELPING &&
				    attr == RAD_TRAVELPING_ZONE_ID) {
					strncpy(zoneid, data, len);
					zoneid[len] = '\0';
					debug(": zoneid: %s", zoneid);
				}
			}
		}
		rad_get_reset(req);

		if (zoneid[0])
			znt = hs_get_zone_by_zoneid(zoneid);
	}

	if (!znt) {
		rad_free_packet(req);
		EXIT();
		return;
	}

	switch (rad_get_code(req)) {
	case RAD_ACCESS_REQUEST:
	case RAD_ACCESS_CHALLENGE:
		type = RADIUS_AUTH;
		break;

	case RAD_ACCOUNTING_REQUEST:
		type = RADIUS_ACCT;
		break;

	default:
		debug(": invalid radius request: %d", rad_get_code(req));
		rad_free_packet(req);
		EXIT();
		return;
	}

	clnt = get_radius_client(znt, ((struct sockaddr_in *)&from)->sin_addr, type);
	if (!clnt) {
		rad_free_packet(req);
		EXIT();
		return;
	}

	if (clnt->id[3] == cwmp__IGD_SCG_RS_Authentication)
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Authentication.Client{i}.RadiusSecret */
		secret = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_RS_Auth_Clnt_i_RadiusSecret);
	else
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusServer.Accounting.Client{i}.RadiusSecret */
		secret = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_RS_Acct_Clnt_i_RadiusSecret);
	if (!secret) {
		rad_free_packet(req);
		EXIT();
		return;
	}

	if (!is_valid_request(req, secret)) {
		rad_free_packet(req);
		EXIT();
		return;
	}

#if defined(SDEBUG)
	while ((attr = rad_get_attr(req, &data, &len)) > 0) {
		if (attr == RAD_VENDOR_SPECIFIC) {
			uint32_t vendor;

			attr = rad_get_vendor_attr(&vendor, &data, &len);
			debug("(): vendor: %d, attr: %d, len: %d", vendor, attr, (int)len);
		} else
			debug("(): attr: %d, len: %d", attr, (int)len);
	}
	rad_get_reset(req);
#endif

	switch (type) {
	case RADIUS_AUTH:
		resp = rad_auth_req(znt, clnt, req);
		break;

	case RADIUS_ACCT:
		resp = rad_acct_req(znt, clnt, req);
		break;

	default:
		break;
	}

	if (resp) {
		r = rad_send_answer_from(w->fd, resp, secret, 0, (struct sockaddr *)&from, msg.msg_namelen, laddr);
		debug("() send result: %d (%d)", (int)r, errno);
	}

	rad_free_packet(resp);
	rad_free_packet(req);

	EXIT();
}

static void acctsrv_ev_cb(EV_P_ ev_io *w, int revents)
{
	authsrv_ev_cb(EV_A_ w, revents);
}

static void add_zone_radius_server(struct rad_setup *setup, tr069_id id, const tr069_selector ssel)
{
	struct rad_server *srv;
	struct tr069_value_table *srvt;

	if ((ssel)[0] != cwmp__InternetGatewayDevice ||
	    (ssel)[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
	    (ssel)[2] != cwmp__IGD_SCG_RadiusClient ||
	    ((ssel)[3] != cwmp__IGD_SCG_RC_Authentication &&
	     (ssel)[3] != cwmp__IGD_SCG_RC_Accounting) ||
	    (ssel)[4] != cwmp__IGD_SCG_RC_Auth_Server ||
	    (ssel)[5] == 0 ||
	    (ssel)[6] != 0) {
		debug(": invalid radius server reference");
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i} */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i} */
	srvt = tr069_get_table_by_selector(ssel);
	if (!srvt) {
		debug(": radius server reference no found");
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.X_DM_RadiusServerStruct */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.X_DM_RadiusServerStruct */
	srv = tr069_get_ptr_by_id(srvt, cwmp__IGD_SCG_RC_Auth_Srv_i_X_DM_RadiusServerStruct);
	if (!srv) {
		debug(": radius server reference is empty");
		return;
	}

	rad_add_server(setup, id, srv);
}

static void add_zone_radius_servers(struct rad_setup *setup, struct tr069_instance *rs)
{
	struct tr069_instance_node *node;

	for (node = tr069_instance_first(rs);
	     node != NULL;
	     node = tr069_instance_next(rs, node)) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AuthServer.{i} */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AcctServer.{i} */

		tr069_selector *ssel;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AuthServer.{i}.Server */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AcctServer.{i}.Server */
		ssel = tr069_get_selector_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Radius_AuthServer_j_Server);
		if (!ssel) {
			debug(": no radius server reference");
			continue;
		}
		add_zone_radius_server(setup, node->instance, *ssel);
	}
}

static void init_zone_radius_servers(struct tr069_value_table *znt __attribute__ ((unused)),
				     struct tr069_value_table *zr,
				     tr069_selector *isel)
{
	struct rad_setup *auths;
	struct rad_setup *accts;

	ENTER();

	auths = rad_setup_open(RADIUS_AUTH, auth_notify_cb, isel);
	accts = rad_setup_open(RADIUS_ACCT, acct_notify_cb, isel);

	if (!auths || !accts) {
		EXIT();
		return;
	}

	struct tr069_instance *rs;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AuthServer */
	rs = tr069_get_instance_ref_by_id(zr, cwmp__IGD_SCG_Zone_i_Radius_AuthServer);
	if (rs)
		add_zone_radius_servers(auths, rs);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AcctServer */
	rs = tr069_get_instance_ref_by_id(zr, cwmp__IGD_SCG_Zone_i_Radius_AcctServer);
	if (rs)
		add_zone_radius_servers(accts, rs);

	/* VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AuthServerServerStruct */
	tr069_set_ptr_by_id(zr, cwmp__IGD_SCG_Zone_i_Radius_X_DM_AuthServerServerStruct, auths);
	/* VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AcctServerServerStruct */
	tr069_set_ptr_by_id(zr, cwmp__IGD_SCG_Zone_i_Radius_X_DM_AcctServerServerStruct, accts);

#if 0
#if defined (HAVE_LIBTOMCRYPT)
	unsigned long len = MAXBLOCKSIZE;
	hash_memory(hash_idx, secret, strlen(secret), &srvp->key, &len) != CRYPT_OK;
#elif defined (HAVE_LIBPOLARSSL)
	sha1(secret, strlen(secret), &srvp->key);
#endif
#endif

	EXIT();
}

static void init_scg_zone_radius(struct tr069_value_table *znt)
{
	struct tr069_value_table *zr;
	tr069_selector *isel;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius */
	zr = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Radius);
	if (!zr) {
		EXIT();
		return;
	}

	isel = malloc(sizeof(tr069_selector));
	if (!isel) {
		EXIT();
		return;
	}
	tr069_selcpy(*isel, znt->id);

	init_zone_radius_servers(znt, zr, isel);

	EXIT();
	return;
}

/* init radius servers for all enabled zones
 *
 * for use only during startup
 */
void init_scg_zones_radius(void)
{
	struct tr069_instance *zone;
	struct tr069_instance_node *zn;

	ENTER();

	init_scg_radius();

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone */
	zone = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0});
	if (!zone) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	for (zn = tr069_instance_first(zone);
	     zn != NULL;
	     zn = tr069_instance_next(zone, zn))
	{
		struct tr069_value_table *znt = DM_TABLE(zn->table);

		/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
		if (!tr069_get_bool_by_id(znt, cwmp__IGD_SCG_Zone_i_Enabled))
			continue;

		init_scg_zone_radius(znt);
		radius_accounting_on(znt);
	}

	EXIT();
}

void stop_scg_zones_radius(void)
{
	struct tr069_instance *zone;
	struct tr069_instance_node *zn;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone */
	zone = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0});
	if (!zone) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	for (zn = tr069_instance_first(zone);
	     zn != NULL;
	     zn = tr069_instance_next(zone, zn))
	{
		struct tr069_value_table *znt = DM_TABLE(zn->table);

		/** VAR: InternetGatewayDevice.LANDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Enabled */
		if (!tr069_get_bool_by_id(znt, cwmp__IGD_SCG_Zone_i_Enabled))
			continue;

		hs_remove_all_clients_from_zone(znt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_NAS_Reboot);
		radius_accounting_off(znt, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_LS_TerminateCause_NAS_Reboot + 1);
	}

	EXIT();
}

void del_IGD_SCG_RC_Auth_Server(const struct tr069_table *kw __attribute__((unused)),
				tr069_id id __attribute__((unused)),
				struct tr069_instance *inst __attribute__((unused)),
				struct tr069_instance_node *node)
{
        char b1[128], b2[128];

	struct tr069_value_table *server = DM_TABLE(node->table);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication */
	int isAuthServer = server->id[3] == cwmp__IGD_SCG_RC_Authentication;

	struct rad_server *srv;
	struct tr069_instance *zones;

	ENTER(": execute for sel: %s (type: %s)",
	      sel2str(b1, server->id), isAuthServer ? "Authentication" : "Accounting");

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.X_DM_RadiusServerStruct */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.X_DM_RadiusServerStruct */
	srv = (struct rad_server *)tr069_get_ptr_by_id(server, cwmp__IGD_SCG_RC_Auth_Srv_i_X_DM_RadiusServerStruct);
	debug(": rad_server: %p", srv);
	if (!srv) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
	zones = tr069_get_instance_ref_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
		cwmp__IGD_X_TPLINO_NET_SessionControl,
		cwmp__IGD_SCG_Zone, 0
	});
	if (zones) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
		for (struct tr069_instance_node *zone = tr069_instance_first(zones);
		     zone != NULL;
		     zone = tr069_instance_next(zones, zone))
		{
			struct tr069_value_table *radius;
			struct tr069_instance *zservers;
			struct tr069_instance_node *zserver;

			tr069_selector sel;

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius */
			if (!(radius = tr069_get_table_by_id(DM_TABLE(zone->table), cwmp__IGD_SCG_Zone_i_Radius)))
				continue;

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AuthServer */
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AcctServer */
			zservers = tr069_get_instance_ref_by_id(radius, isAuthServer
					? cwmp__IGD_SCG_Zone_i_Radius_AuthServer
					: cwmp__IGD_SCG_Zone_i_Radius_AcctServer);
			if (!zservers)
				continue;

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AuthServer.{i} */
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AcctServer.{i} */
			zserver = find_instance(zservers, cwmp__IGD_SCG_Zone_i_Radius_AuthServer_j_Server,
						T_SELECTOR, &init_DM_SELECTOR(&server->id, 0));
			if (!zserver)
				continue;

			logx(LOG_WARNING, "%s: have to clean up reference %s to server %s", __FUNCTION__,
			     sel2str(b1, DM_TABLE(zserver->table)->id), sel2str(b2, server->id));

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AuthServer.{i}.Server */
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.AcctServer.{i}.Server */
			tr069_selcpy(sel, DM_TABLE(zserver->table)->id);
			sel[7] = cwmp__IGD_SCG_Zone_i_Radius_AuthServer_j_Server;
			sel[8] = 0;
			/* ensure that action is enqueued */
			tr069_set_selector_by_selector(sel, NULL, DV_UPDATED);
		}

		/*
		 * remove all references from zones to this server
		 * should result in the rad_server being removed from all rad_setups
		 * however, rad_server_nodes may still exist (referenced by requests enqueued to the server)
		 * referencing this server
		 */
		exec_actions_pre();
		exec_actions();
	}

	/*
	 * free all the request queues associated with this server and care about
	 * their requests - remaining rad_server_nodes should be garbage collected
	 */
	rad_free_server(srv);

	EXIT();
}

void del_IGD_SCG_RC_Acct_Server(const struct tr069_table *, tr069_id,
				struct tr069_instance *, struct tr069_instance_node *)
			       __attribute__((alias ("del_IGD_SCG_RC_Auth_Server")));

void dm_rad_srv_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
        char b1[128];
#endif
	struct tr069_instance_node *node;

	ENTER(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	if (type != DM_CHANGE) {
		EXIT_MSG(": already handled");
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i} */
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i} */
	if (!(node = tr069_get_instance_node_by_selector(sel))) {
		EXIT();
		return;
	}

	update_scg_radius_server(DM_TABLE(node->table));

	EXIT();
}

void dm_zone_rad_srv_action(const tr069_selector sel, enum dm_action_type type)
{
#if defined(SDEBUG)
        char b1[128];
#endif
	struct rad_setup *rs;
	tr069_selector rads;

	debug(": execute for sel: %s, type: %d", sel2str(b1, sel), type);

	/* VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AuthServerServerStruct */
	/* VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AcctServerServerStruct */
	tr069_selcpy(rads, sel);
	rads[6] = 0;

	switch (sel[5]) {
	case cwmp__IGD_SCG_Zone_i_Radius_AuthServer:
		rads[5] = cwmp__IGD_SCG_Zone_i_Radius_X_DM_AuthServerServerStruct;
		break;

	case cwmp__IGD_SCG_Zone_i_Radius_AcctServer:
		rads[5] = cwmp__IGD_SCG_Zone_i_Radius_X_DM_AcctServerServerStruct;
		break;

	default:
		EXIT();
		return;
	}

	rs = (struct rad_setup *)tr069_get_ptr_by_selector(rads);
	debug(": rad_setup: %s, ptr: %p", sel2str(b1, rads), rs);
	if (!rs) {
		EXIT();
		return;
	}

	if (type != DM_ADD)
		rad_remove_server(rs, sel[6]);

	if (type != DM_DEL) {
		tr069_selector *ssel;

		tr069_selcpy(rads, sel);
		rads[7] = cwmp__IGD_SCG_Zone_i_Radius_AuthServer_j_Server;
		rads[8] = 0;

		debug(": server ref: %s", sel2str(b1, rads));
		ssel = tr069_get_selector_by_selector(rads);
		if (ssel) {
			debug(": server: %s", sel2str(b1, *ssel));

			add_zone_radius_server(rs, sel[6], *ssel);
		}
	}
	EXIT();
}

#if 0
static void init_iv(unsigned char* iv, unsigned long *len)
{
#if defined (HAVE_LIBTOMCRYPT)
	yarrow_read(iv, cipher_descriptor[cipher_idx].block_length, &prng);
	*len = cipher_descriptor[cipher_idx].block_length;
#elif defined (HAVE_LIBPOLARSSL)
	for (int i = 0; i < AES_BLOCK_LEN / sizeof(int); i++)
		((uint16_t *)iv)[i] = havege_rand(&h_state);
#endif
	*len = AES_BLOCK_LEN;
}
#endif

#if 0
#if defined (HAVE_LIBTOMCRYPT)
static int enc(unsigned char* iv,
	       const unsigned char* in, int inlen,
	       unsigned char *out, unsigned long *outlen)
{
	symmetric_CBC cbc;
	unsigned char buf[MAXBLOCKSIZE];
	int len, err;
	unsigned int bsize = cipher_descriptor[cipher_idx].block_length;

	if (*outlen < bsize)
		return 0;

	/* start up CBC mode */
	if ((err = cbc_start(cipher_idx, iv, key,
			      AES_BLOCK_LEN, 0, &cbc) ) != CRYPT_OK) {
		printf("cbc_start error: %s\n", error_to_string(err));
		return 0;
	}

	len = 0;

	while (*outlen >= bsize && inlen > 0) {
		if (inlen < bsize) {
			memset(buf, 0, bsize);
			memcpy(buf, in, inlen);
			inlen = 0;
		} else {
			memcpy(buf, in, bsize);
			inlen -= bsize;
			in += bsize;
		}

		if ((err = cbc_encrypt(buf, out, bsize, &cbc) ) != CRYPT_OK) {
			printf("cbc_encrypt error: %s\n", error_to_string(err));
			return 0;
		}
		out += bsize;
		len += bsize;
		*outlen -= bsize;
	}

	*outlen = len;
	return 1;
}

#elif defined (HAVE_LIBPOLARSSL)
static int enc(unsigned char *iv,
	       const unsigned char *in, int inlen,
	       unsigned char *out, unsigned long *outlen)
{
	int len = 0;
	int padlen;
	aes_context aes_ctx;

	padlen = AES_BLOCK_LEN - (inlen % AES_BLOCK_LEN);

	if (*outlen + padlen < inlen)
		return 0;

	memset(&aes_ctx, 0, sizeof(aes_ctx));
	aes_setkey_enc(&aes_ctx, key, 128);

	/* aes cbc */
	while (inlen > 0 || padlen != 0) {
		int i = 0;

		memcpy(out, iv, AES_BLOCK_LEN);
		for(; i < AES_BLOCK_LEN && i < inlen; i++)
			out[i] ^= in[i];

		if (i < AES_BLOCK_LEN) {
			for (; i < AES_BLOCK_LEN; i++)
				out[i] ^= padlen;
			padlen = 0;
		}

		aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, out, out);

		iv = out;
		in += AES_BLOCK_LEN;
		out += AES_BLOCK_LEN;
		inlen -= AES_BLOCK_LEN;
		len += AES_BLOCK_LEN;
	}

	*outlen = len;
	return 1;
}
#endif

#endif

static void tr069_set_string_len_by_id(struct tr069_value_table *tab, tr069_id id, const char *s, int len)
{
	char buf[256];

	if (len > 255)
		return;

	strncpy(buf, s, len);
	buf[len] = '\0';

	tr069_set_string_by_id(tab, id, buf);
}

static void rad_auth_vendor_wispr(struct tr069_value_table *clnt,
				  int attr, const void *data, int len)
{
	switch (attr) {
		case RAD_WISPR_REDIRECTION_URL:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RedirectUrl */
			tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RedirectUrl, data, len);
			break;

		case RAD_WISPR_BANDWIDTH_MIN_UP:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMinUp */
			tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMinUp, rad_cvt_int(data));
			break;

		case RAD_WISPR_BANDWIDTH_MAX_UP:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMaxUp */
			tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMaxUp, rad_cvt_int(data));
			break;

		case RAD_WISPR_BANDWIDTH_MIN_DOWN:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMinDown */
			tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMinDown, rad_cvt_int(data));
			break;

		case RAD_WISPR_BANDWIDTH_MAX_DOWN:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMaxDown */
			tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMaxDown, rad_cvt_int(data));
			break;

		default:
			break;
	}
}

static void clear_reply_msg(const tr069_selector client)
{
	tr069_selector sel;

	tr069_selcpy(sel, client);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ReplyMessage */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ReplyMessage;
	sel[8] = 0;

	tr069_del_table_by_selector(sel);
}

static void add_reply_msg(const tr069_selector client, const char *msg, int len)
{
	tr069_selector sel;
        struct tr069_instance_node *rpl;
        tr069_id id;

	ENTER();

	tr069_selcpy(sel, client);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ReplyMessage */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ReplyMessage;
	sel[8] = 0;


        id = TR069_ID_AUTO_OBJECT;
        if ((rpl = tr069_add_instance_by_selector(sel, &id)) == NULL) {
                EXIT();
                return;
	}
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ReplyMessage.{i}.Message */
	tr069_set_string_len_by_id(DM_TABLE(rpl->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RplM_k_Message, msg, len);

	EXIT();
}

static void add_rad_class(const tr069_selector client, const char *class, int len)
{
	tr069_selector sel;
        struct tr069_instance_node *cls;
        tr069_id id;

	ENTER();

	tr069_selcpy(sel, client);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusClass */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RadiusClass;
	sel[8] = 0;

        id = TR069_ID_AUTO_OBJECT;
        if ((cls = tr069_add_instance_by_selector(sel, &id)) == NULL) {
                EXIT();
                return;
	}
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusClass.{i} */
	tr069_set_string_len_by_id(DM_TABLE(cls->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RClass_k_Class, class, len);

	EXIT();
}

static void clear_rad_class(const tr069_selector client)
{
	tr069_selector sel;

	tr069_selcpy(sel, client);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusClass */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RadiusClass;
	sel[8] = 0;

	tr069_del_table_by_selector(sel);
}

static void add_rad_access_rule(const tr069_selector client, const char *rule, int len)
{
	int t,v;
	int policy;
	tr069_selector sel;
	struct tr069_instance_node *cls;
	tr069_id id;

	ENTER();

	for (v = len - 1; v > 0; v--)
		if (rule[v] == ',')
			break;
	if (v == 0) {
		EXIT();
		return;
	}

	for (t = v - 1; t > 0; t--)
		if (rule[t] == ',')
			break;
	if (t == 0) {
		EXIT();
		return;
	}

	if (strncasecmp(&rule[v+1], "Accept", 6) == 0)
		policy = cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_ACR_k_ACRPol_Accept;
	else if (strncasecmp(&rule[v+1], "Deny", 4) == 0)
		policy = cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_ACR_k_ACRPol_Deny;
	else {
		EXIT();
		return;
	}

	tr069_selcpy(sel, client);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessRule */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessRule;
	sel[8] = 0;

        id = TR069_ID_AUTO_OBJECT;
        if ((cls = tr069_add_instance_by_selector(sel, &id)) == NULL) {
                EXIT();
                return;
	}
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessRule.{i}.From */
	tr069_set_string_len_by_id(DM_TABLE(cls->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ACR_k_From, rule, t);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessRule.{i}.To */
	tr069_set_string_len_by_id(DM_TABLE(cls->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ACR_k_To, &rule[t+1], v - t - 1);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessRule.{i}.Policy */
	tr069_set_enum_by_id(DM_TABLE(cls->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ACR_k_Policy, policy);

	EXIT();
}

static void clear_rad_access_rule(const tr069_selector client)
{
	tr069_selector sel;

	tr069_selcpy(sel, client);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessRule */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessRule;
	sel[8] = 0;

	tr069_del_table_by_selector(sel);
}

struct rca_data {
	tr069_selector client;
	char sessionid[256];
	char username[256];
	char password[256];
	char tag[256];

	authentication_cb ok_cb;
	authentication_cb final_cb;
	void *user;
};

static char *safe_strncpy(char *d, const char *s, size_t len)
{
	if (s) {
		len--;
		if (strlen(s) < len)
			len = strlen(s);

		strncpy(d, s, len);
		d[len] = '\0';
	} else
		d[0] = '\0';

	return d;
}

static void set_radius_result(struct tr069_value_table *clnt, int result)
{
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAuthenticationResult */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthenticationResult, result);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthorizationResult */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthorizationResult, result);
}

static void set_provider_radius(struct tr069_value_table *clnt)
{
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationProvider */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationProvider, AUTH_PROV_RADIUS);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthorizationProvider */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthorizationProvider, AUTH_PROV_RADIUS);

}

int
radius_authentication_request(const tr069_selector zone __attribute__((unused)), struct tr069_value_table *znt,
			      const tr069_selector client, struct tr069_value_table *clnt,
			      const char *sessionid, const char *username, const char *password,
			      const char *tag, int request_cui, int auth_only,
			      authentication_cb ok_cb, authentication_cb final_cb, void *user)
{
	int rc;
	struct tr069_value_table *rst;
	tr069_selector *host;
	struct rad_setup *auths;
	struct rca_data *rca;
	tr069_selector *if_sel;
	struct rad_handle *radh;
	struct rad_packet *radp;
	const char *val;
	const binary_t *bval;
	struct in_addr extip;
	struct in_addr clntip;

	ENTER();

	dm_assert(znt != NULL);
	dm_assert(clnt != NULL);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_DM_OutstandingRadiusAuthenticationRequest */
	radh = tr069_get_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_OutstandingRadiusAuthenticationRequest);
	if (radh) {
		debug("(): pending request, kill it");
		tr069_set_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_OutstandingRadiusAuthenticationRequest, NULL);
		rad_notify(-1, radh);
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius */
	rst = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Radius);
	if (!rst) {
		set_radius_result(clnt, AUTH_STATE_ERROR);
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AuthServerServerStruct */
	auths = tr069_get_ptr_by_id(rst, cwmp__IGD_SCG_Zone_i_Radius_X_DM_AuthServerServerStruct);
	if (!auths) {
		set_radius_result(clnt, AUTH_STATE_ERROR);
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	rca = malloc(sizeof(struct rca_data));
	if (!rca) {
		set_radius_result(clnt, AUTH_STATE_ERROR);
		EXIT();
		return DM_OOM;
	}

	safe_strncpy(rca->sessionid, sessionid, sizeof(rca->sessionid));
	safe_strncpy(rca->username, username, sizeof(rca->username));
	safe_strncpy(rca->password, password, sizeof(rca->password));
	safe_strncpy(rca->tag, tag, sizeof(rca->tag));
	tr069_selcpy(rca->client, client);
	rca->ok_cb = ok_cb;
	rca->final_cb = final_cb;
	rca->user = user;

	if (!(radh = rad_auth_open(rca))) {
		debug("Failed to create radius handle");
		free(rca);
		set_radius_result(clnt, AUTH_STATE_ERROR);
		return DM_ERROR;
	}
	radp = rad_init_request(radh, RAD_ACCESS_REQUEST);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationRequestState */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationRequestState, AUTH_REQ_PENDING);


	extip = get_wan_ip(1);
	if (extip.s_addr != INADDR_NONE) {
		rad_put_addr(radp, RAD_NAS_IP_ADDRESS, extip);
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.NASIdentifier */
	if ((val = tr069_get_string_by_id(rst, cwmp__IGD_SCG_Zone_i_Radius_NASIdentifier)))
		rad_put_string(radp, RAD_NAS_IDENTIFIER, val);

/* FIXME: reenable
	   rad_put_int   (radp, RAD_NAS_PORT,           client->port_id);
*/
	if (auth_only)
		rad_put_int(radp, RAD_SERVICE_TYPE, RAD_AUTHORIZE_ONLY);
	else
		rad_put_int(radp, RAD_SERVICE_TYPE, RAD_FRAMED);
	rad_put_int(radp, RAD_FRAMED_PROTOCOL, RAD_PPP);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	clntip = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
	if (clntip.s_addr != INADDR_ANY && clntip.s_addr != INADDR_NONE)
		rad_put_addr(radp, RAD_FRAMED_IP_ADDRESS, clntip);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	clntip = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);
	if (clntip.s_addr != INADDR_ANY && clntip.s_addr != INADDR_NONE)
		rad_put_vendor_addr(radp,
				    RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_NAT_IP_ADDRESS,
				    clntip);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress)))
		rad_put_string(radp, RAD_CALLING_STATION_ID, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.CalledStationId */
	if ((bval = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_CalledStationId))) {
		rad_put_attr(radp, RAD_CALLED_STATION_ID, bval->data, bval->len);
	} else {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.LANDevice */
		if_sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_LANDevice);
		if (if_sel) {
			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANEthernetInterfaceConfig.1.MACAddress */
			val = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
						cwmp__IGD_LANDevice,
						(*if_sel)[2],
						cwmp__IGD_LANDev_i_LANEthernetInterfaceConfig,
						1,
						cwmp__IGD_LANDev_i_EthCfg_j_MACAddress, 0});
			if (val)
				rad_put_string(radp, RAD_CALLED_STATION_ID, val);
		}
	}

/* FIXME: reenable
	if (client->port_type > 0)
		rad_put_int   (radp, RAD_NAS_PORT_TYPE, client->port_type);
*/
	rad_put_int(radp, RAD_NAS_PORT_TYPE, RAD_ETHERNET);

	if (username)
		rad_put_string(radp, RAD_USER_NAME, username);
	if (password)
		rad_put_string(radp, RAD_USER_PASSWORD, password);

	if (request_cui)
		rad_put_attr(radp, RAD_CHARGEABLE_USER_IDENTITY, "\0", 1);
	else
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ChargeableUserIdentity */
		if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ChargeableUserIdentity)))
			rad_put_string(radp, RAD_CHARGEABLE_USER_IDENTITY, val);

	if (tag)
		rad_put_vendor_string(radp, RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_ACCESS_CLASS_ID, tag);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.TerminationAction */
	if (tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction) ==
	    cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction_RADIUS_Request) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusState */
		if ((bval = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RadiusState)))
			rad_put_attr(radp, RAD_STATE, bval->data, bval->len);
	}

#if 0
	else {
		unsigned char iv[MAXBLOCKSIZE];
		unsigned char buf[1024];
		unsigned long blen;

		//		rad_put_string(radp, RAD_USER_PASSWORD, "tposs Gateway");

		init_iv(iv, &blen);
		rad_put_vendor_attr(radp,
				    RAD_VENDOR_TRAVELPING,
				    RAD_TRAVELPING_ENC_IV,
				    iv, blen);

		blen = sizeof(buf);
		if (enc(iv, passwd, strlen(passwd), buf, &blen)) {
			rad_put_vendor_attr(radp,
					    RAD_VENDOR_TRAVELPING,
					    RAD_TRAVELPING_PASSWORD,
					    buf, blen);
		}
	}
#endif

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId)))
		rad_put_string(radp, RAD_ACCT_MULTI_SESSION_ID, val);

	if (sessionid)
		rad_put_string(radp, RAD_ACCT_SESSION_ID, sessionid);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RelatedSessionId */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RelatedSessionId)))
		rad_put_vendor_string(radp,
				      RAD_VENDOR_TRAVELPING,
				      RAD_TRAVELPING_RELATED_SESSION_ID,
				      val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.UserAgent */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_UserAgent)))
		rad_put_vendor_string(radp,
				      RAD_VENDOR_TRAVELPING,
				      RAD_TRAVELPING_USERAGENT,
				      val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentCircuitId */
	if ((bval = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentCircuitId)))
		rad_put_vendor_attr(radp,
				    RAD_VENDOR_DSLF,
				    RAD_DSLF_AGENT_CIRCUIT_ID,
				    bval->data, bval->len);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentRemoteId */
	if ((bval = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentRemoteId)))
		rad_put_vendor_attr(radp,
				    RAD_VENDOR_DSLF,
				    RAD_DSLF_AGENT_REMOTE_ID,
				    bval->data, bval->len);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId)))
		rad_put_vendor_string(radp,
				      RAD_VENDOR_TRAVELPING,
				      RAD_TRAVELPING_LOCATION_ID,
				      val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Host */
	host = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Host);
	if (host) {
		struct tr069_value_table *hst;

		hst = tr069_get_table_by_selector(*host);
		if (hst) {
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.HostName */
			if ((val = tr069_get_string_by_id(hst, cwmp__IGD_LANDev_i_Hosts_H_j_HostName)))
				rad_put_vendor_string(radp,
						      RAD_VENDOR_TRAVELPING,
						      RAD_TRAVELPING_HOSTNAME,
						      val);

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPRequestOptionList */
			if ((bval = tr069_get_binary_by_id(hst, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPRequestOptionList)))
				rad_put_vendor_attr(radp,
						    RAD_VENDOR_TRAVELPING,
						    RAD_TRAVELPING_DHCP_REQUEST_OPTION_LIST,
						    bval->data, bval->len);

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPParameterRequestList */
			if ((bval = tr069_get_binary_by_id(hst, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPParameterRequestList)))
				rad_put_vendor_attr(radp,
						    RAD_VENDOR_TRAVELPING,
						    RAD_TRAVELPING_DHCP_PARAMETER_REQUEST_LIST,
						    bval->data, bval->len);
		}
	}

	/* BT special requirement - make this configurable in the future or handle at NIL ??? */
	rad_put_int(radp, RAD_EVENT_TIMESTAMP, time(NULL));
	rad_put_message_authentic(radp);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationRequestState */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationRequestState, AUTH_REQ_PENDING);

	tr069_set_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_OutstandingRadiusAuthenticationRequest, radh);
	rc = rad_send_request(auths, radh);

	EXIT();
	return rc == 0 ? DM_OK : DM_ERROR;
}

static void clear_cta(struct tr069_value_table *clnt)
{
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusState */
	tr069_set_binary_data_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RadiusState, 0, NULL);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.TerminationAction */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction_Default);
}

/* clear all non persisten fields */
static void clear_old_session_attrs(struct tr069_value_table *clnt)
{
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RequestedNATIPAddress */
	tr069_set_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATIPAddress, (struct in_addr){ .s_addr = INADDR_NAS_SELECT });
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RequestedNATPoolId */
	tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATPoolId, NULL);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RedirectUrl */
	tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RedirectUrl, NULL);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMinUp */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMinUp, 0);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMaxUp */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMaxUp, 0);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMinDown */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMinDown, 0);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.BandwidthMaxDown */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_BandwidthMaxDown, 0);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_TPOSS_ReplyCode */
	tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_TPOSS_ReplyCode, 0);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxInputOctets */
	tr069_set_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxInputOctets, 0);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxOutputOctets */
	tr069_set_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxOutputOctets, 0);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxTotalOctets */
	tr069_set_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxTotalOctets, 0);
}

static void auth_notify_cb(int res, struct rad_handle *radh,
			   void *user __attribute__ ((unused)), void *rca_data)
{
	struct rad_packet *resp;
	struct rca_data *rca = rca_data;
	struct tr069_value_table *clnt;
	const void *data;
	size_t len;
	int attr;
#if defined (SDEBUG)
	char b1[128];
#endif

	struct {
		unsigned int id;
		int haveTarget;
		char target[32];
	} monitor = {
		.id = 0,
		.haveTarget = 0
	};

	debug("got response %d for %s\n", res, sel2str(b1, rca->client));

	clnt = tr069_get_table_by_selector(rca->client);
	if (!clnt) {
		debug("unable to locate client entry");
		goto out;
	}

	/* TerminationAction is not persistent, clear it */
	clear_cta(clnt);

	resp = rad_response(radh);

	debug("(): client radh: %p", tr069_get_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_OutstandingRadiusAuthenticationRequest));
	tr069_set_ptr_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_DM_OutstandingRadiusAuthenticationRequest, NULL);

	if (res == -1) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationRequestState */
		tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationRequestState, AUTH_REQ_ERROR);

		set_radius_result(clnt, AUTH_STATE_ERROR);

		debug("radius error: %s", rad_strerror(radh));
		clear_reply_msg(rca->client);
		add_reply_msg(rca->client, "Server failure", strlen("Server failure"));
		goto out;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationRequestState */
	tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationRequestState, AUTH_REQ_COMPLETED);

	if (res == RAD_ACCESS_ACCEPT) {
		struct {
			int session_timeout:1;
			int idle_timeout:1;
			int interim_interval:1;
		} rflags = {
			.session_timeout = 0,
			.idle_timeout = 0,
			.interim_interval = 0,
		};
		char exit_ac_tag[256] = "\0";

		if (rca && rca->ok_cb)
			rca->ok_cb(AUTH_STATE_ACCEPTED, clnt, rca->user);

		clear_rad_class(rca->client);
		clear_reply_msg(rca->client);
		clear_rad_access_rule(rca->client);
		clear_old_session_attrs(clnt);

		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username, rca->username);
		tr069_set_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Password, rca->password);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InterimUpdateInterval */
		tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InterimUpdateInterval, time2ticks(600));

		while ((attr = rad_get_attr(resp, &data, &len)) > 0) {
			debug(" got attr %d, len: %d", attr, (int)len);
			switch (attr) {
			case RAD_REPLY_MESSAGE:
				add_reply_msg(rca->client, data, len);
				break;
			case RAD_CLASS:
				fprintf(stderr, "got class: '%.*s', len: %d\n", (int)len, (char *)data, (int)len);
				add_rad_class(rca->client, data, len);
				break;
			case RAD_SESSION_TIMEOUT:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTimeout */
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout, time2ticks(rad_cvt_int(data)));
				rflags.session_timeout = 1;
				break;
			case RAD_IDLE_TIMEOUT:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTimeout */
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeout, time2ticks(rad_cvt_int(data)));
				rflags.idle_timeout = 1;
				break;
			case RAD_ACCT_INTERIM_INTERVAL:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InterimUpdateInterval */
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InterimUpdateInterval, time2ticks(rad_cvt_int(data)));
				rflags.interim_interval = 1;
				break;
			case RAD_CHARGEABLE_USER_IDENTITY:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ChargeableUserIdentity */
				tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ChargeableUserIdentity, data, len);
				break;
			case RAD_STATE:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusState */
				tr069_set_binary_data_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RadiusState, len, data);
				break;
			case RAD_TERMINATION_ACTION:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.TerminationAction */
				tr069_set_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_TerminationAction, rad_cvt_int(data));
				break;
			case RAD_VENDOR_SPECIFIC: {
				uint32_t vendor;

				attr = rad_get_vendor_attr(&vendor, &data, &len);
				debug(" got vendor %d, attr %d, len: %d", vendor, attr, (int)len);
				switch (vendor) {
					case RAD_VENDOR_WISPR:
						rad_auth_vendor_wispr(clnt, attr, data, len);
						break;

					case RAD_VENDOR_TRAVELPING:
						switch (attr) {
						case RAD_TRAVELPING_AUTH_REPLY_CODE:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_TPOSS_ReplyCode */
							tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_TPOSS_ReplyCode, rad_cvt_int(data));
							break;

						case RAD_TRAVELPING_ACCESS_CLASS_ID:
							if (len >= sizeof(rca->tag))
								len = sizeof(rca->tag) - 1;
							memcpy(&rca->tag, data, len);
							rca->tag[len] = '\0';
							break;

						case RAD_TRAVELPING_LOCATION_ID:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
							tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId, data, len);
							break;

						case RAD_TRAVELPING_MONITOR_SESSION_ID:
							monitor.id = rad_cvt_int(data);
							break;

						case RAD_TRAVELPING_MONITOR_ID:
							if (len > sizeof(monitor.target) - 1)
								len = sizeof(monitor.target) - 1;
							strncpy(monitor.target, data, len);
							monitor.target[len] = '\0';
							monitor.haveTarget = 1;
							break;

						case RAD_TRAVELPING_NAT_IP_ADDRESS:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RequestedNATIPAddress */
							tr069_set_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATIPAddress, rad_cvt_addr(data));
							break;

						case RAD_TRAVELPING_NAT_POOL_ID:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RequestedNATPoolId */
							tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RequestedNATPoolId, data, len);
							break;

						case RAD_TRAVELPING_MAX_INPUT_OCTETS:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxInputOctets */
							tr069_set_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxInputOctets, rad_cvt_int64(data));
							break;

						case RAD_TRAVELPING_MAX_OUTPUT_OCTETS:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxOutputOctets */
							tr069_set_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxOutputOctets, rad_cvt_int64(data));
							break;

						case RAD_TRAVELPING_MAX_TOTAL_OCTETS:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxTotalOctets */
							tr069_set_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxTotalOctets, rad_cvt_int64(data));
							break;

						case RAD_TRAVELPING_EXIT_ACCESS_CLASS_ID:
							if (len >= sizeof(exit_ac_tag))
								len = sizeof(exit_ac_tag) - 1;
							memcpy(&exit_ac_tag, data, len);
							exit_ac_tag[len] = '\0';
							break;

						case RAD_TRAVELPING_ACCESS_RULE:
							add_rad_access_rule(rca->client, data, len);
							break;

						case RAD_TRAVELPING_ACCESS_GROUP_ID:
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessGroupId */
							tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessGroupId, data, len);
							break;

						case RAD_TRAVELPING_KEEP_ALIVE_TIMEOUT: {
							unsigned int timeout;
							ticks_t vt_old, vt_new;

							timeout = rad_cvt_int(data);
							/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.KeepAliveTimout */
							tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_KeepAliveTimeout, timeout);

							if (timeout != 0) {
								vt_new = ticks() + time2ticks(timeout);
								/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
								vt_old = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ValidTill);
								if (vt_new > vt_old)
									/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
									tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ValidTill, vt_new);
							} else
								/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ValidTill */
								tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ValidTill, 0);
							break;
						}

						default:
							break;
						}
						break;

					default:
						break;
				}
				break;
			}
			default:
				break;
			}
		}

		tr069_selector acsel, *st = NULL, *ex_st = NULL;

		tr069_selcpy(acsel, clnt->id);
		acsel[4] = cwmp__IGD_SCG_Zone_i_AccessClasses;
		acsel[5] = cwmp__IGD_SCG_Zone_i_ACs_AccessClass;
		acsel[6] = 0;

		struct tr069_instance *acs = NULL;
		if (rca->tag[0] || exit_ac_tag[0])
			/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass */
			acs = tr069_get_instance_ref_by_selector(acsel);

		if (rca->tag[0] && acs) {
			struct tr069_instance_node *ac;

			/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
			/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
			ac = find_instance(acs, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId, T_STR, &init_DM_STRING(rca->tag, 0));
			if (ac)
				st = &DM_TABLE(ac->table)->id;
		}
		if (!st) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.OnlineAccessClass */
			acsel[4] = cwmp__IGD_SCG_Zone_i_OnlineAccessClass;
			acsel[5] = 0;
			st = tr069_get_selector_by_selector(acsel);
		}
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
		tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass, *st);

		struct tr069_value_table *act;
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
		act = tr069_get_table_by_selector(*st);

		if (exit_ac_tag[0] && acs) {
			struct tr069_instance_node *ac;

			/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
			/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
			ac = find_instance(acs, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId, T_STR, &init_DM_STRING(exit_ac_tag, 0));
			if (ac)
				ex_st = &DM_TABLE(ac->table)->id;
		} else if (act) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.ExitRequestAccessClass */
			ex_st = tr069_get_selector_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_ExitRequestAccessClass);
		}

		if (!act) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitAccessClass */
			tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitAccessClass, NULL);
		} else
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitAccessClass */
			tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitAccessClass,
						 *tr069_get_selector_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_ExitAccessClass));
#if 0
		if (!ex_st) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitRequestAccessClass */
			tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitRequestAccessClass, NULL);
		} else
#endif
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ExitRequestAccessClass */
			tr069_set_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ExitRequestAccessClass, *ex_st);

		if (act && (!rflags.session_timeout || !rflags.idle_timeout || !rflags.interim_interval)) {
			if (!rflags.session_timeout)
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTimeout */
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.SessionTimeout */
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout,
						      time2ticks(tr069_get_uint_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_SessionTimeout)));

			if (!rflags.idle_timeout)
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IdleTimeout */
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.IdleTimeout */
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IdleTimeout,
						      time2ticks(tr069_get_uint_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_IdleTimeout)));

			if (!rflags.interim_interval)
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InterimUpdateInterval */
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.InterimUpdateInterval */
				tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InterimUpdateInterval,
						      time2ticks(tr069_get_uint_by_id(act, cwmp__IGD_SCG_Zone_i_ACs_AC_j_InterimUpdateInterval)));
		}

		set_provider_radius(clnt);
		set_radius_result(clnt, AUTH_STATE_ACCEPTED);
	} else {
		clear_reply_msg(rca->client);

		while ((attr = rad_get_attr(resp, &data, &len)) > 0) {
			switch (attr) {
			case RAD_REPLY_MESSAGE:
				add_reply_msg(rca->client, data, len);
				break;

			case RAD_CHARGEABLE_USER_IDENTITY:
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ChargeableUserIdentity */
				tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ChargeableUserIdentity, data, len);
				break;

			case RAD_VENDOR_SPECIFIC: {
				uint32_t vendor;

				attr = rad_get_vendor_attr(&vendor, &data, &len);
				debug("got vendor %x, attr %x", vendor, attr);
				switch (vendor) {
				case RAD_VENDOR_TRAVELPING:
					switch (attr) {
					case RAD_TRAVELPING_AUTH_REPLY_CODE:
						/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_TPOSS_ReplyCode */
						tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_TPOSS_ReplyCode, rad_cvt_int(data));
						break;

					case RAD_TRAVELPING_LOCATION_ID:
						/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
						tr069_set_string_len_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId, data, len);
						break;

					case RAD_TRAVELPING_MONITOR_SESSION_ID:
						monitor.id = rad_cvt_int(data);
						break;

					case RAD_TRAVELPING_MONITOR_ID:
						if (len > sizeof(monitor.target) - 1)
							len = sizeof(monitor.target) - 1;
						strncpy(monitor.target, data, len);
						monitor.target[len] = '\0';
						monitor.haveTarget = 1;
						break;

					default:
						break;
					}
					break;

				default:
					break;
				}
			}
			default:
				break;
			}
		}

		set_radius_result(clnt, AUTH_STATE_DENIED);
	}

	if (monitor.haveTarget) {
		if (*monitor.target)
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorId */
			tr069_set_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorId, monitor.id);
		client_set_monitor_id(clnt, monitor.target, cwmp___IGD_SCG_Mon_i_Type_RADIUS);
	}

out:
	if (rca && rca->final_cb) {
		int auth_res = AUTH_STATE_ERROR;
		
		if (clnt)
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAuthorizationResult */
			auth_res = tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthorizationResult);

		rca->final_cb(auth_res, clnt, rca->user);
	}
	free(rca);

	/* we might have changed something important, exec notifications for it */
	if (getCfgSessionStatus() == CFGSESSION_INACTIVE)
		exec_pending_notifications();
}

int
radius_accounting_request(int request_type, struct tr069_value_table *clnt, int reason)
{
	tr069_selector zone;
	struct tr069_value_table *znt;
	struct tr069_value_table *rst;
	struct rad_setup *accts;
	tr069_selector *clnt_sel;
	tr069_selector *if_sel;
	tr069_selector *np_sel;
	tr069_selector *ac_sel;
	struct tr069_instance *class;
	struct tr069_instance_node *node;
	struct rad_handle *radh;
	struct rad_packet *radp;
	int res;
	struct in_addr extip;
	struct in_addr clntip;
	unsigned int nat_port = 0;
	const char *val;
	const binary_t *bval;

	ENTER();

	dm_assert(clnt != NULL);

	tr069_selcpy(zone, clnt->id);
	zone[4] = 0;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	znt = tr069_get_table_by_selector(zone);
	dm_assert(znt);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius */
	rst = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Radius);
	if (!rst) {
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AcctServerServerStruct */
	accts = tr069_get_ptr_by_id(rst, cwmp__IGD_SCG_Zone_i_Radius_X_DM_AcctServerServerStruct);
	if (!accts) {
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	clnt_sel = malloc(sizeof(tr069_selector));
	if (!clnt_sel)
		return DM_OOM;
	tr069_selcpy(*clnt_sel, clnt->id);

	if (!(radh = rad_acct_open(clnt_sel))) {
		debug("Failed to create radius handle");
		return DM_ERROR;
	}

	radp = rad_init_request(radh, RAD_ACCOUNTING_REQUEST);

	if (request_type == RAD_STOP && reason)
		rad_put_int(radp, RAD_ACCT_TERMINATE_CAUSE, reason);

	extip = get_wan_ip(1);
	if (extip.s_addr != INADDR_NONE) {
		rad_put_addr(radp, RAD_NAS_IP_ADDRESS, extip);
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.NASIdentifier */
	if ((val = tr069_get_string_by_id(rst, cwmp__IGD_SCG_Zone_i_Radius_NASIdentifier)))
		rad_put_string(radp, RAD_NAS_IDENTIFIER, val);

/* FIXME: reenable
	rad_put_int   (radp, RAD_NAS_PORT,           client->port_id);
*/

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationProvider */
	switch (tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationProvider)) {
	case AUTH_PROV_RADIUS:
		rad_put_int(radp, RAD_ACCT_AUTHENTIC, RAD_AUTH_RADIUS);
		break;

	case AUTH_PROV_BACKEND:
		rad_put_int(radp, RAD_ACCT_AUTHENTIC, RAD_AUTH_REMOTE);
		break;

	default:
		rad_put_int(radp, RAD_ACCT_AUTHENTIC, RAD_AUTH_LOCAL);
		break;
	}

	rad_put_int(radp, RAD_SERVICE_TYPE,       RAD_FRAMED);
	rad_put_int(radp, RAD_FRAMED_PROTOCOL,    RAD_PPP);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	rad_put_addr(radp, RAD_FRAMED_IP_ADDRESS, tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress));

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	clntip = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);
	if (clntip.s_addr != INADDR_ANY && clntip.s_addr != INADDR_NONE)
		rad_put_vendor_addr(radp,
				    RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_NAT_IP_ADDRESS,
				    clntip);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
	nat_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart);
	if (nat_port)
		rad_put_vendor_int(radp,
				   RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_NAT_PORT_START,
				   nat_port);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
	nat_port = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd);
	if (nat_port)
		rad_put_vendor_int(radp,
				   RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_NAT_PORT_END,
				   nat_port);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPool */
	np_sel = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPool);
	if (np_sel) {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.NATPool.{i}.NatPoolId */
		val = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
					cwmp__IGD_X_TPLINO_NET_SessionControl,
					cwmp__IGD_SCG_NATPool,
					(*np_sel)[3],
					cwmp__IGD_SCG_NP_i_NatPoolId, 0});
		if (val)
			rad_put_vendor_string(radp,
					      RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_NAT_POOL_ID,
					      val);
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress)))
		rad_put_string(radp, RAD_CALLING_STATION_ID, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.LANDevice */
	if_sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_LANDevice);
	if (if_sel) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANEthernetInterfaceConfig.1.MACAddress */
		val = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
					cwmp__IGD_LANDevice,
					(*if_sel)[2],
					cwmp__IGD_LANDev_i_LANEthernetInterfaceConfig,
					1,
					cwmp__IGD_LANDev_i_EthCfg_j_MACAddress, 0});
		if (val)
			rad_put_string(radp, RAD_CALLED_STATION_ID, val);
	}

/* FIXME: reenable
	if (client->port_type > 0)
		rad_put_int   (radp, RAD_NAS_PORT_TYPE, client->port_type);
*/
	rad_put_int(radp, RAD_NAS_PORT_TYPE, RAD_ETHERNET);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username)))
		rad_put_string(radp, RAD_USER_NAME, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ChargeableUserIdentity */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ChargeableUserIdentity)))
		rad_put_string(radp, RAD_CHARGEABLE_USER_IDENTITY, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
	ac_sel = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);
	if (ac_sel) {
		struct tr069_value_table *ac;

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
		ac = tr069_get_table_by_selector(*ac_sel);
		if (ac) {
			const char *tag;

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i}.AccessClassId */
			tag = tr069_get_string_by_id(ac, cwmp__IGD_SCG_Zone_i_ACs_AC_j_AccessClassId);
			if (tag)
				rad_put_vendor_string(radp, RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_ACCESS_CLASS_ID, tag);
		}
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusClass */
	class = tr069_get_instance_ref_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RadiusClass);
	if (class)
		for (node = tr069_instance_first(class);
		     node != NULL;
		     node = tr069_instance_next(class, node)) {
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RadiusClass.{i}.Class */
			if ((val = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RClass_k_Class))) {
				fprintf(stderr, "adding class: '%s', len: %d\n", val, (int)strlen(val));
				rad_put_attr(radp, RAD_CLASS, val, strlen(val));
			}
		}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId)))
		rad_put_string(radp, RAD_ACCT_MULTI_SESSION_ID, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AcctSessionId */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId)))
		rad_put_string(radp, RAD_ACCT_SESSION_ID, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RelatedSessionId */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RelatedSessionId)))
		rad_put_vendor_string(radp,
				      RAD_VENDOR_TRAVELPING,
				      RAD_TRAVELPING_RELATED_SESSION_ID,
				      val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.UserAgent */
	if ((val = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_UserAgent)))
		rad_put_vendor_string(radp,
				      RAD_VENDOR_TRAVELPING,
				      RAD_TRAVELPING_USERAGENT,
				      val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentCircuitId */
	if ((bval = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentCircuitId)))
		rad_put_vendor_attr(radp,
				    RAD_VENDOR_DSLF,
				    RAD_DSLF_AGENT_CIRCUIT_ID,
				    bval->data, bval->len);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentRemoteId */
	if ((bval = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentRemoteId)))
		rad_put_vendor_attr(radp,
				    RAD_VENDOR_DSLF,
				    RAD_DSLF_AGENT_REMOTE_ID,
				    bval->data, bval->len);

	if (request_type != RAD_START) {
		ticks_t sesst;
		uint64_t cnt;

		if (request_type != RAD_STOP) {
			sesst = ticks();

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
			sesst -= tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime);
			if (sesst < 0)
				sesst = 0;
		} else
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTime */
			sesst = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime);

		rad_put_int(radp, RAD_ACCT_SESSION_TIME, sesst / 10);

		cnt = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets);
		rad_put_int(radp, RAD_ACCT_INPUT_OCTETS, cnt & 0xffffffff);
		rad_put_int(radp, RAD_ACCT_INPUT_GIGAWORDS, cnt >> 32);

		cnt = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets);
		rad_put_int(radp, RAD_ACCT_OUTPUT_OCTETS, cnt & 0xffffffff);
		rad_put_int(radp, RAD_ACCT_OUTPUT_GIGAWORDS, cnt >> 32);

		rad_put_int(radp, RAD_ACCT_INPUT_PACKETS, tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InPackets) & 0xffffffff);
		rad_put_int(radp, RAD_ACCT_OUTPUT_PACKETS,  tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutPackets) & 0xffffffff);
	}
	rad_put_int(radp, RAD_ACCT_STATUS_TYPE, request_type);
	rad_put_int(radp, RAD_EVENT_TIMESTAMP, time(NULL));

	res = rad_send_request(accts, radh);

	/* wipe radius class attributes on stop */
	if (request_type == RAD_STOP) {
		clear_cta(clnt);
		clear_rad_class(clnt->id);
		clear_rad_access_rule(clnt->id);
	}

	EXIT();
	return DM_OK;
}

static void acct_notify_cb(int res, struct rad_handle *radh,
			   void *user __attribute__ ((unused)), void *sel)
{
	const tr069_selector *client = sel;
	struct tr069_value_table *clnt;
#if defined (SDEBUG)
	char b1[128];
#endif

	ENTER();

	if (!client) {
		/*
		 * this happens for status only requests
		 */
		free(sel);
		EXIT();
		return;
	}

	debug("got response %d for %s\n", res, sel2str(b1, *client));

	if (res == -1) {
		debug("radius error: %s", rad_strerror(radh));
		free(sel);
		EXIT();
		return;
	}

	clnt = tr069_get_table_by_selector(*client);
	if (!clnt) {
		debug("unable to locate client entry");
		free(sel);
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAccountingUpdate */
	tr069_set_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAccountingUpdate, ticks());

	free(sel);
	EXIT();
}

static void radius_accounting_status(struct tr069_value_table *znt, int status, int reason)
{
	struct tr069_value_table *rst;
	struct rad_setup *accts;
	tr069_selector *if_sel;
	struct rad_handle *radh;
	struct rad_packet *radp;
	const char *val;
	struct in_addr extip;

	ENTER();

	dm_assert(znt != NULL);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius */
	rst = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Radius);
	if (!rst) {
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.X_DM_AcctServerServerStruct */
	accts = tr069_get_ptr_by_id(rst, cwmp__IGD_SCG_Zone_i_Radius_X_DM_AcctServerServerStruct);
	if (!accts) {
		EXIT();
		return;
	}

	if (!(radh = rad_acct_open(NULL))) {
		debug("Failed to create radius handle");
		EXIT();
		return;
	}

	radp = rad_init_request(radh, RAD_ACCOUNTING_REQUEST);
	rad_put_int(radp, RAD_ACCT_STATUS_TYPE, status);

	if (status == RAD_ACCOUNTING_OFF)
		rad_put_int(radp, RAD_ACCT_TERMINATE_CAUSE, reason);

	extip = get_wan_ip(1);
	if (extip.s_addr != INADDR_NONE) {
		rad_put_addr(radp, RAD_NAS_IP_ADDRESS, extip);
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Radius.NASIdentifier */
	if ((val = tr069_get_string_by_id(rst, cwmp__IGD_SCG_Zone_i_Radius_NASIdentifier)))
		rad_put_string(radp, RAD_NAS_IDENTIFIER, val);

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.LANDevice */
	if_sel = tr069_get_selector_by_id(znt, cwmp__IGD_SCG_Zone_i_LANDevice);
	if (if_sel) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANEthernetInterfaceConfig.1.MACAddress */
		val = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
					cwmp__IGD_LANDevice,
					(*if_sel)[2],
					cwmp__IGD_LANDev_i_LANEthernetInterfaceConfig,
					1,
					cwmp__IGD_LANDev_i_EthCfg_j_MACAddress, 0});
		if (val)
			rad_put_string(radp, RAD_CALLED_STATION_ID, val);
	}

        /** VAR: InternetGatewayDevice.DeviceInfo.HardwareVersion */
	if ((val = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
						cwmp__IGD_DeviceInfo,
						cwmp__IGD_DevInf_HardwareVersion, 0})))
		rad_put_vendor_string(radp, RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_FW_VARIANT, val);

        /** VAR: InternetGatewayDevice.DeviceInfo.SoftwareVersion */
	if ((val = tr069_get_string_by_selector((tr069_selector) {cwmp__InternetGatewayDevice,
						cwmp__IGD_DeviceInfo,
						cwmp__IGD_DevInf_SoftwareVersion, 0})))
		rad_put_vendor_string(radp, RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_FW_VERSION, val);

	rad_send_request(accts, radh);

	EXIT();
}

void radius_accounting_on(struct tr069_value_table *znt)
{
	radius_accounting_status(znt, RAD_ACCOUNTING_ON, 0);
}

void radius_accounting_off(struct tr069_value_table *znt, int reason)
{
	radius_accounting_status(znt, RAD_ACCOUNTING_OFF, reason);
}

#if 0
int set_IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationRequestState(struct tr069_value_table *base,
							       tr069_id id __attribute__ ((unused)),
							       const struct tr069_element *elem __attribute__ ((unused)),
							       DM_VALUE *st,
							       DM_VALUE val)
{
	tr069_selector zone;
	struct tr069_value_table *znt;

        ENTER();

        debug("(): AuthenticationRequestState, old: %d, new: %d\n", DM_ENUM(*st), DM_ENUM(val));

        if (DM_ENUM(*st) != AUTH_REQ_INITIATED &&
	    DM_ENUM(*st) != AUTH_REQ_PENDING) {
		set_DM_ENUM(*st, DM_ENUM(val));

		tr069_selcpy(zone, base->id);
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
		zone[4] = 0;
		znt = tr069_get_table_by_selector(zone);

		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Password */
		radius_authentication_request(zone, znt, base->id, base,
					      tr069_get_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username),
					      tr069_get_string_by_id(base, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Password),
					      NULL, 0,
					      NULL, NULL, NULL);
	}

	EXIT();
	return 0;
}
#endif

#define RadiusAuthSrvStatsAlias(x)						\
        DM_VALUE x(const struct tr069_value_table *, tr069_id, const struct tr069_element *, DM_VALUE) __attribute__ ((alias ("get_IGD_SCG_RC_Auth_Srv_i_Stats")))

RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_AccessRequests);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_Retransmissions);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_AccessAccepts);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_AccessRejects);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_AccessChallenges);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_MalformedAccessResponses);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_BadAuthenticators);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_PendingRequests);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_Timeouts);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_UnknownTypes);
RadiusAuthSrvStatsAlias(get_IGD_SCG_RC_Auth_Srv_i_Stats_PacketsDropped);

static DM_VALUE get_IGD_SCG_RC_Auth_Srv_i_Stats(const struct tr069_value_table *base,
					   tr069_id id __attribute__ ((unused)),
					   const struct tr069_element *elem __attribute__ ((unused)),
					   DM_VALUE val)
{
	struct rad_server *srv;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.cwmp__IGD_SCG_RC_i_X_DM_RadiusServerStruct */
	srv = tr069_get_ptr_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_RadiusClient,
				cwmp__IGD_SCG_RC_Authentication,
				cwmp__IGD_SCG_RC_Auth_Server,
				base->id[5],
				cwmp__IGD_SCG_RC_Auth_Srv_i_X_DM_RadiusServerStruct, 0});
	if (!srv) {
		EXIT();
		return val;
	}

	switch (id) {
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.AccessRequests */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_AccessRequests:
		set_DM_UINT(val, srv->stats.requests);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.Retransmissions */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_Retransmissions:
		set_DM_UINT(val, srv->stats.retransmissions);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.AccessAccepts */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_AccessAccepts:
		set_DM_UINT(val, srv->stats.access_accepts);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.AccessRejects */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_AccessRejects:
		set_DM_UINT(val, srv->stats.access_rejects);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.AccessChallenges */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_AccessChallenges:
		set_DM_UINT(val, srv->stats.access_challenges);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.MalformedAccessResponses */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_MalformedAccessResponses:
		set_DM_UINT(val, srv->stats.malformed_responses);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.BadAuthenticators */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_BadAuthenticators:
		set_DM_UINT(val, srv->stats.bad_authenticators);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.PendingRequests */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_PendingRequests:
		set_DM_UINT(val, srv->stats.pending_requests);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.Timeouts */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_Timeouts:
		set_DM_UINT(val, srv->stats.timeouts);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.UnknownTypes */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_UnknownTypes:
		set_DM_UINT(val, srv->stats.unknown_types);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Authentication.Server.{i}.Stats.PacketsDropped */
	case cwmp__IGD_SCG_RC_Auth_Srv_i_Stats_PacketsDropped:
		set_DM_UINT(val, srv->stats.packets_dropped);
		break;

	default:
		break;
	}

	EXIT();
	return val;
}

#define RadiusAcctSrvStatsAlias(x)						\
        DM_VALUE x(const struct tr069_value_table *, tr069_id, const struct tr069_element *, DM_VALUE) __attribute__ ((alias ("get_IGD_SCG_RC_Acct_Srv_i_Stats")))

RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_Requests);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_Retransmissions);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_Responses);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_MalformedResponses);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_BadAuthenticators);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_PendingRequests);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_Timeouts);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_UnknownTypes);
RadiusAcctSrvStatsAlias(get_IGD_SCG_RC_Acct_Srv_i_Stats_PacketsDropped);

static DM_VALUE get_IGD_SCG_RC_Acct_Srv_i_Stats(const struct tr069_value_table *base,
					   tr069_id id __attribute__ ((unused)),
					   const struct tr069_element *elem __attribute__ ((unused)),
					   DM_VALUE val)
{
	struct rad_server *srv;

	ENTER();

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.cwmp__IGD_SCG_RC_i_X_DM_RadiusServerStruct */
	srv = tr069_get_ptr_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_RadiusClient,
				cwmp__IGD_SCG_RC_Accounting,
				cwmp__IGD_SCG_RC_Acct_Server,
				base->id[5],
				cwmp__IGD_SCG_RC_Auth_Srv_i_X_DM_RadiusServerStruct, 0});

	if (!srv) {
		EXIT();
		return val;
	}

	switch (id) {
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.Requests */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_Requests:
		set_DM_UINT(val, srv->stats.requests);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.Retransmissions */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_Retransmissions:
		set_DM_UINT(val, srv->stats.retransmissions);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.Responses */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_Responses:
		set_DM_UINT(val, srv->stats.responses);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.MalformedResponses */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_MalformedResponses:
		set_DM_UINT(val, srv->stats.malformed_responses);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.BadAuthenticators */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_BadAuthenticators:
		set_DM_UINT(val, srv->stats.bad_authenticators);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.PendingRequests */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_PendingRequests:
		set_DM_UINT(val, srv->stats.pending_requests);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.Timeouts */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_Timeouts:
		set_DM_UINT(val, srv->stats.timeouts);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.UnknownTypes */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_UnknownTypes:
		set_DM_UINT(val, srv->stats.unknown_types);
		break;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.RadiusClient.Accounting.Server.{i}.Stats.PacketsDropped */
	case cwmp__IGD_SCG_RC_Acct_Srv_i_Stats_PacketsDropped:
		set_DM_UINT(val, srv->stats.packets_dropped);
		break;

	default:
		break;
	}

	EXIT();
	return val;
}
