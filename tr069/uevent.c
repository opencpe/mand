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
#include <linux/types.h>
#include <linux/netlink.h>

#include <ev.h>

#define SDEBUG
#include "debug.h"

#include "ifup.h"
#include "uevent.h"
#include "utils/logx.h"

static ev_io ev_uevent;

static void handle_uevent(char *buf, size_t len)
{
	char *action = NULL;
	char *subsystem = NULL;
	char *interface = NULL;

	size_t pos = 0;

	ENTER();

	while (pos < len) {
		char *s, *t;

		s = &buf[pos];
		if (!*s)
			break;

		debug(": %3d, '%s'", pos, s);
		pos += strlen(s) + 1;

		t = strsep(&s, "=");
		if (s && t) {
			if (strcmp("ACTION", t) == 0)
				action = s;
			else if (strcmp("SUBSYSTEM", t) == 0)
				subsystem = s;
			else if (strcmp("INTERFACE", t) == 0)
				interface = s;
		}
	}

	if (subsystem && strcmp("net", subsystem) == 0) {
		if (action && interface)
			do_uevent(subsystem, action, interface, NULL);
	}

	EXIT();
}

static void ev_uevent_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	char buf[2048];
	int n;

	struct sockaddr_nl nla;
        struct iovec iov;
        struct msghdr msg = {
                .msg_name = (void *) &nla,
                .msg_namelen = sizeof(struct sockaddr_nl),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = NULL,
                .msg_controllen = 0,
                .msg_flags = 0,
        };
        struct cmsghdr *cmsg;

	memset(buf, 0, sizeof(buf));
        iov.iov_len = sizeof(buf);
        iov.iov_base = &buf;

	ENTER();

        while ((n = recvmsg(w->fd, &msg, MSG_DONTWAIT) > 0)) {
		if (iov.iov_len < n ||
		    msg.msg_flags & MSG_TRUNC) {
			logx(LOG_INFO, "uevent: message tuncated");
		} else if (msg.msg_flags & MSG_CTRUNC) {
			logx(LOG_INFO, "uevent: controll message tuncated");
		}

		handle_uevent(&buf, iov.iov_len);
		memset(buf, 0, sizeof(buf));
	}

/*
	while ((len = recv(w->fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)) {
		for (int i = 0; i < len; i += strlen(buf + i) + 1)
			logx(LOG_INFO, "uevent: %d, %d, %s\n", len, i, buf + i);
	}
*/

	EXIT();
}


void init_uevent(EV_P)
{
	int fd;
	struct sockaddr_nl nls;

	ENTER();

	/* Open hotplug event netlink socket */
	memset(&nls,0,sizeof(struct sockaddr_nl));
	nls.nl_family = AF_NETLINK;
	nls.nl_pid = getpid();
	nls.nl_groups = -1;

	fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (fd == -1) {
		EXIT();
		return;
	}

	/* Listen to netlink socket */
	if (bind(fd, (void *)&nls, sizeof(struct sockaddr_nl))) {
		EXIT();
		return;
	}

	//fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	ev_io_init(&ev_uevent, ev_uevent_cb, fd, EV_READ);
	ev_io_start(EV_A_ &ev_uevent);

	EXIT();
}
