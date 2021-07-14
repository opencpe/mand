/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>

#define SDEBUG
#include "debug.h"

#include "inet_helper.h"

static int ctl_socket = -1;

int get_inet_ctl_socket(void)
{
	if (ctl_socket < 0) {
		ctl_socket = socket(PF_INET, SOCK_DGRAM, 0);
		if (ctl_socket < 0) {
			debug("(): socket(PF_INET): %m");
			return -1;
		}
		fcntl(ctl_socket, F_SETFD, fcntl(ctl_socket, F_GETFD) | FD_CLOEXEC);
	}
	return ctl_socket;
}

int do_ethflags(const char *iface, uint32_t flags, uint32_t mask)
{
        struct ifreq ifr;
        int s;
        int err;

        s = get_inet_ctl_socket();
        if (s < 0)
                return -1;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
        err = ioctl(s, SIOCGIFFLAGS, &ifr);
        if (err) {
                debug("(): SIOCGIFFLAGS: %m");
                return -1;
        }
        if ((ifr.ifr_flags ^ flags) & mask) {
                ifr.ifr_flags &= ~mask;
                ifr.ifr_flags |= mask & flags;
                err = ioctl(s, SIOCSIFFLAGS, &ifr);
                if (err)
                        debug("(): SIOCSIFFLAGS: %m");
        }
        return err;
}

struct in_addr getifip(const char *iface)
{
        int s;
        struct ifreq ifr;
        struct in_addr ret;

        ret.s_addr = INADDR_NONE;

        s = get_inet_ctl_socket();
        if (s < 0)
                return ret;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
        ifr.ifr_addr.sa_family = AF_INET;
        if (ioctl(s, SIOCGIFADDR, &ifr) == 0)
                ret = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

        return ret;
}

struct in_addr getifdstip(const char *iface)
{
        int s;
        struct ifreq ifr;
        struct in_addr ret;

        ret.s_addr = INADDR_NONE;

        s = get_inet_ctl_socket();
        if (s < 0)
                return ret;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
        ifr.ifr_addr.sa_family = AF_INET;
        if (ioctl(s, SIOCGIFDSTADDR, &ifr) == 0)
                ret = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

        return ret;
}
