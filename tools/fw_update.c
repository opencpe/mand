#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <signal.h>
#include <sys/reboot.h>

#include "mtd.h"
#include "ftools.h"

int sys_shutdown_system(unsigned long magic);

static void usage(void) {
#if defined(WITH_KEXEC)
	fprintf(stderr, "Usage: fwupdate [--js] [--silent] [--kexec] <file> <dest>\n");
#else
	fprintf(stderr, "Usage: fwupdate [--js] [--silent] <file> <dest>\n");
#endif
}

static int verbose_flag = FLAG_VERBOSE;
static int perc = 0;

static void fw_finish(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (verbose_flag & FLAG_VERBOSE) {
		fprintf(stderr, "\nflash result: ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, " (%d)\n", code);
	}

	if (verbose_flag & FLAG_JS) {
		fprintf(stdout, "<script type=\"text/javascript\">installFinisched(%d, \"", code);
		vfprintf(stdout, fmt, ap);
		fprintf(stdout, "\");</script>\n");
		fflush(stdout);
	}

	va_end(ap);
}

static void fw_progress(const char *msg, int state, int total, int current, const char *unit)
{
	if (verbose_flag & FLAG_VERBOSE) {
		fprintf(stderr, "\r%s: %d%s/%u%s (%d%%)",
			msg, current, unit, total, unit, PERCENTAGE(current, total));
		if (current == total)
			fprintf(stderr, "\n");
	}
	if (verbose_flag & FLAG_JS) {
		int p = PERCENTAGE(current, total);
		if (perc != p) {
			fprintf(stdout, "<script type=\"text/javascript\">setStatus(%d, %d);</script>\n", state, p);
			fflush(stdout);
			perc = p;
		}
	}
}

struct _fw_callbacks fw_callbacks = {
	.fw_finish = fw_finish,
	.fw_progress = fw_progress
};

int main(int argc, char *argv[])
{
	FILE *inf;
	int r = 1;
	int size;

	static struct option long_options[] = {
		{"silent", no_argument, &verbose_flag, 0},
		{"js",     no_argument, &verbose_flag, FLAG_JS},
		{"force",  no_argument, &verbose_flag, FLAG_FORCE | FLAG_VERBOSE},
#if defined(WITH_KEXEC)
		{"kexec",  no_argument, &try_kexec, 1},
#endif
		{NULL, 0, 0, 0},
	};

	while (1) {
		int c;
		int option_index = 0;

		c = getopt_long(argc, argv, "",
				long_options, &option_index);

		if (c == -1)
			break;

		if (c != 0) {
			fprintf(stderr, "invalid option\n");
			usage();
			exit(1);
		}
	}

	if (argc - optind != 2) {
		usage();
		exit(1);
	}

#ifdef _POSIX_SOURCE
        struct sigaction sigact;

        sigact.sa_handler = SIG_IGN;
        sigemptyset (&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction (SIGHUP, &sigact, NULL);
#else
        signal (SIGHUP, SIG_IGN);
#endif

	if (verbose_flag & FLAG_VERBOSE)
		fprintf(stderr, "doing firmware update\n");

	inf = fopen(argv[optind], "r");
	if (!inf) {
		perror("open");
		exit(2);
	}

	r = validate_tpfu(inf, &size);
	if (r == 0 || ((r & ERR_FLAG_MASK) == 0 && verbose_flag & FLAG_FORCE)) {
		if (verbose_flag & FLAG_VERBOSE)
			fprintf(stderr, "writing firmware to flash... %d\n", r);
		r = write_firmware(inf, size, argv[optind + 1]);
	}

	if (verbose_flag & FLAG_VERBOSE) {
		if (r)
			fprintf(stderr, "failed!\n");
		else
			fprintf(stderr, "success!\n");
	}

	fclose(inf);

	if (r == 0) {
		fclose(stdout);
		sys_shutdown_system(RB_AUTOBOOT);
	}

	return 0;
}
