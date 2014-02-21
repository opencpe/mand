#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <signal.h>
#include <sys/reboot.h>

#include "mtd.h"

#if !defined(SFX_OFFS)
#define SFX_OFFS 0
#endif

int main(int argc, char *argv[])
{
	FILE *inf;
	int r;

	fprintf(stderr, "doing firmware update\n");

#ifdef _POSIX_SOURCE
        struct sigaction sigact;

        sigact.sa_handler = SIG_IGN;
        sigemptyset (&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction (SIGHUP, &sigact, NULL);
#else
        signal (SIGHUP, SIG_IGN);
#endif

	inf = fopen(argv[0], "r");
	if (!inf) {
		perror("open");
		exit(2);
	}

	fprintf(stderr, "writing firmware to flash...\n");
	fseek(inf, SFX_OFFS, SEEK_SET);
	if ((r = write_firmware(inf, 0, "linux", 1)))
		fprintf(stderr, "failed!\n");
	else
		fprintf(stderr, "success!\n");

	fclose(inf);

	if (r == 0)
		sys_shutdown_system(RB_AUTOBOOT);

	return 0;
}
