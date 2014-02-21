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

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "tr069_async_resolve.h"
#include "cares-ev.h"

#include "tr069_store.h"

#define SDEBUG
#include "debug.h"

static struct ev_ares ev_ea;
ares_channel dns_channel;

void async_resolve(void *arg, int status, int timeouts, struct hostent *host)
{
	const struct tr069_value_table *rtab;
	struct in_addr ip;
	cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_e dir;

	ENTER();

	debug("(): status: %d, timeouts: %d\n", status, timeouts);

	if ((rtab = tr069_get_table_by_selector((tr069_selector) {cwmp__InternetGatewayDevice, cwmp__IGD_X_TPLINO_NET_DNSResolver, 0})) == NULL) {
		debug("(): couldn't get DNSResolver from storage\n");
		return;
	}

	if (status != ARES_SUCCESS) {
		debug("(): error: %s\n", ares_strerror(status));
		tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_State, cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Error);
	} else {
		/** VAR: InternetGatewayDevice.X_TPLINO_NET_DNSResolver.Direction */
		dir = tr069_get_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_Direction);
		switch(dir) {
			case cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Normal:
				memcpy(&ip , host->h_addr_list[0], sizeof(struct in_addr));
				debug("(): resolved: %s\n", inet_ntoa(ip));
				tr069_set_ipv4_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_IP, ip);
				tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_State, cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Complete);
				break;
			case cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Reverse:
				debug("(): resolved: %s\n", host->h_name);
				tr069_set_string_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_HostName, host->h_name);
				tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_State, cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Complete);
				break;
			case cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Not_Configured:
			default:
				tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_State, cwmp___IGD_X_TPLINO_NET_DNSResolver_State_Error);
				debug("(): DNSResolver direction misconfigured\n");
		}
	}
	tr069_set_enum_by_id(rtab, cwmp__IGD_X_TPLINO_NET_DNSResolver_Direction, cwmp___IGD_X_TPLINO_NET_DNSResolver_Direction_Not_Configured);

	if(eva_usage > 0)
		eva_usage--;
	debug("(): DNSResolver done. Usecount now is %d\n", eva_usage);


	EXIT();
}

int tr069d_evdns_init(const struct in_addr *nameserver)
{
	int status;
	struct ares_options options = {
		.sock_state_cb      = ares_ev_sock_state_cb,
		.sock_state_cb_data = &ev_ea,
	};

	ENTER();

	debug("(): Initialising resolver.\n");

	if (nameserver != NULL && nameserver->s_addr != INADDR_ANY) {
		options.nservers = 1;
		options.servers  = nameserver;
		debug("(): Using %s as nameserver\n", inet_ntoa(*nameserver));
	} else {
		options.nservers = 0;
		debug("(): Using local nameserver\n");
	}

	debug("(): Usecount is %d\n", eva_usage);
	if(eva_usage < 0) {
		ares_init_ev(&ev_ea);
		status = ares_init_options(&dns_channel, &options, ARES_OPT_SOCK_STATE_CB | (options.nservers ? ARES_OPT_SERVERS : 0));
		if (status != ARES_SUCCESS)
			return -1;
		ares_start_ev(&ev_ea, dns_channel);

		eva_usage = 0;
	}

	eva_usage++;

	EXIT();

	return 0;
}
