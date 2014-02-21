#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <string.h>
#include <netdb.h>

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_autogen.h"

#define PRI_DEVICE "eth0";

char *getifmac(const char *dev, char *buf)
{
        int s;
        struct ifreq ifr;
        char *ret = NULL;

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
                perror("socket(AF_INET)");
                return NULL;
        }

        memset(&ifr, 0, sizeof(ifr));

        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0) {
                snprintf(buf, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                        (unsigned char)(ifr.ifr_hwaddr.sa_data[0] & 0xff),
                        (unsigned char)(ifr.ifr_hwaddr.sa_data[1] & 0xff),
                        (unsigned char)(ifr.ifr_hwaddr.sa_data[2] & 0xff),
                        (unsigned char)(ifr.ifr_hwaddr.sa_data[3] & 0xff),
                        (unsigned char)(ifr.ifr_hwaddr.sa_data[4] & 0xff),
                        (unsigned char)(ifr.ifr_hwaddr.sa_data[5] & 0xff));
                ret = buf;
        }

        close(s);
        return ret;
}

void init_hw_defaults(const char *dev)
{
        char buf[20];
	const char *s;

	/** VAR: InternetGatewayDevice.DeviceInfo.SerialNumber */
	s = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							   cwmp__IGD_DeviceInfo,
							   cwmp__IGD_DevInf_SerialNumber, 0});
	if (s && *s)
		return;

	char *mac = getifmac(dev, buf);
	if (mac) {
		/** VAR: InternetGatewayDevice.DeviceInfo.SerialNumber */
		tr069_set_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							       cwmp__IGD_DeviceInfo,
							       cwmp__IGD_DevInf_SerialNumber, 0}, mac, DV_UPDATED);
		if (default_deserialized)
			generate_auto_defaults(mac);
	}
	if (default_deserialized)
		free_auto_default_store();
}
