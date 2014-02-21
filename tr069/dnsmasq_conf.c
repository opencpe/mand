#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include "tr069_token.h"
#include "tr069_store.h"

#define DNSMASQ_CONF "/etc/dnsmasq.conf"
#define DNSMASQ_PID "/var/run/dnsmasq.pid"
#define RESOLV_CONF "/var/etc/resolv.conf"
#define DHCP_LEASES "/var/run/dhcp.leases"
#define WAN_DEVICE "vlan1";
#define PPP_DEVICE "ppp0";

int dnsmasq_reconf()
{
	FILE *fout, *fpid;
	int i, pid;
	char *wan_device = WAN_DEVICE;
	char *domain = NULL;

	fout = fopen(DNSMASQ_CONF, "w+");
	if (fout)
		return 0;

	fprintf(fout, "domain-needed\nbogus-priv\nfilterwin2k\nexpand-hosts\n");
	fprintf(fout, "resolv-file=%s\n", RESOLV_CONF);

	/** VAR: InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Enabled */
	tr069_selector t1 = {1, 12, 1, 7, 1, 8, 1, 1, 0};
	if (tr069_get_bool_by_selector(t1)) {
		wan_device = PPP_DEVICE;
	}
	fprintf(fout, "except-interface=%s\n", wan_device);

	fprintf(fout, "local=/%s/\n", domain);
	fprintf(fout, "domain=%s\n", domain);

	fclose(fout);

	fpid = fopen(DNSMASQ_PID, "r");
	if (fpid) {
		if (fscanf(fpid, "%d", &pid) == 1)
			kill(pid, SIGTERM);
		fclose(fpid);
	}

	return 1;
}
