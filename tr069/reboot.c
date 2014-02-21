#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sys/reboot.h>
#include <sys/mount.h>

const char * const sys_shutdown_format = "\r%s\n";
extern int sys_shutdown_system(unsigned long magic)
{
        int pri = LOG_KERN|LOG_NOTICE|LOG_FACMASK;
        const char *message;

        /* Don't kill ourself */
        signal(SIGTERM, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        setpgrp();

        /* Allow Ctrl-Alt-Del to reboot system. */
#ifndef RB_ENABLE_CAD
#define RB_ENABLE_CAD   0x89abcdef
#endif
        reboot(RB_ENABLE_CAD);

        openlog("fwupd", 0, pri);

        message = "\nThe system is going down NOW !!";
        syslog(pri, "%s", message);
        printf(sys_shutdown_format, message);

        sync();

        /* Send signals to every process _except_ pid 1 */
        message = "Sending SIGTERM to all processes.";
        syslog(pri, "%s", message);
        printf(sys_shutdown_format, message);

        kill(-1, SIGTERM);
        sleep(1);
        sync();

        message = "Sending SIGKILL to all processes.";
        syslog(pri, "%s", message);
        printf(sys_shutdown_format, message);

        kill(-1, SIGKILL);
        sleep(1);
        sync();

	message = "Unmounting JFFS2 partition.";
	syslog(pri, "%s", message);
	printf(sys_shutdown_format, message);

	for (int i = 5; i && umount("/jffs") && errno == EBUSY; i--)
		sleep(1);
	sync();
	sleep(1);

        reboot(magic);
        return 0; /* Shrug */
}
