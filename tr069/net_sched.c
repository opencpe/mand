#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tr069_token.h"
#include "tr069_store.h"

//#define SDEBUG
#include "debug.h"

#include "ifup.h"

void wan_sched_init(const char *iface,
		    const tr069_selector ifref  __attribute__ ((unused)))
{
	unsigned int up, down;

	ENTER();

#if 0
	/** VAR: InternetGatewayDevice.LANDevice.1.HotSpotConfig.MaxBandwidthUp */
	up = tr069_get_uint_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							 cwmp__IGD_LANDevice,
							 1,
							 cwmp__IGD_LANDev_i_HotSpotConfig,
							 cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthUp, 0 });
	/** VAR: InternetGatewayDevice.LANDevice.1.HotSpotConfig.MaxBandwidthDown */
	down = tr069_get_uint_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							   cwmp__IGD_LANDevice,
							   1,
							   cwmp__IGD_LANDev_i_HotSpotConfig,
							   cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthDown, 0 });

	if (!up || !down) {
		EXIT();
		return;
	}

	/* root qdisc */
	vasystem("tc qdisc add dev %s root handle 1: htb default 12", iface);

	/* class for global limit */
	vasystem("tc class add dev %s parent 1: classid 1:1 htb rate %dbps ceil %dbps quantum 5000", iface, up, up);

	/* class for other (non hotspot) traffic */
	vasystem("tc class add dev %s parent 1:1 classid 1:12 htb rate %dbps ceil %dbps quantum 5000", iface, up, up);
	/* (e)sfq qdisc for other traffic */
	vasystem("tc qdisc add dev %s parent 1:12 handle 40: sfq perturb 10", iface);
#endif

	EXIT();
}

void lan_sched_init(const char *iface, const tr069_selector ifref)
{
	unsigned int up, down;

	ENTER();

#if 0
	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthUp */
	up = tr069_get_uint_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							 cwmp__IGD_LANDevice,
							 ifref[2],
							 cwmp__IGD_LANDev_i_HotSpotConfig,
							 cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthUp, 0 });
	/** VAR: InternetGatewayDevice.LANDevice.{i}.HotSpotConfig.MaxBandwidthDown */
	down = tr069_get_uint_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
							   cwmp__IGD_LANDevice,
							   ifref[2],
							   cwmp__IGD_LANDev_i_HotSpotConfig,
							   cwmp__IGD_LANDev_i_HSCfg_MaxBandwidthDown, 0 });

	if (!up || !down) {
		EXIT();
		return;
	}

	/* root qdisc */
	vasystem("tc qdisc add dev %s root handle 1: htb default 12", iface);

	/* class for global limit */
	vasystem("tc class add dev %s parent 1: classid 1:1 htb rate %dbps ceil %dbps quantum 5000", iface, down, down);

	/* class for other (non hotspot) traffic */
	vasystem("tc class add dev %s parent 1:1 classid 1:12 htb rate %dbps ceil %dbps quantum 5000", iface, down, down);
	/* (e)sfq qdisc for other traffic */
	vasystem("tc qdisc add dev %s parent 1:12 handle 40: sfq perturb 10", iface);
#endif

	EXIT();
}

void net_sched_init(void)
{
	ENTER();

	insmod("sch_htb");
	insmod("sch_red");
	insmod("sch_sfq");

	EXIT();
}
