#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>

#include "mtd.h"
#include "ftools.h"
#include "ipkg_tools.h"

static int verbose_flag = FLAG_VERBOSE;
static int perc = 0;

void fw_finish(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (verbose_flag & FLAG_VERBOSE) {
		fprintf(stderr, "\ninstall result: ");
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, " (%d)\n", code);
	}

	if (verbose_flag & FLAG_JS) {
		fprintf(stdout, "<script type=\"text/javascript\">flashFinisched(%d, \"", code);
		vfprintf(stdout, fmt, ap);
		fprintf(stdout, "\");</script>\n");
		fflush(stdout);
	}

	va_end(ap);
}

void fw_progress(const char *msg, int state, int total, int current, const char *unit)
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

static void usage(void)
{
	fprintf(stderr, "Usage: ipkg -i <file>\n"
		        "       ipkg -r <package>\n");
}

int main(int argc, char *argv[])
{
	FILE *inf;
	int what = 0;
	int size;
	int verbose = 0;

	static struct option long_options[] = {
		{"install", no_argument, 0, 'i'},
		{"remove",  no_argument, 0, 'r'},
		{"silent",  no_argument, &verbose_flag, 0},
		{"js",      no_argument, &verbose_flag, FLAG_JS},
		{"nosign",  no_argument, &verbose_flag, FLAG_NO_SIGN | FLAG_VERBOSE},
		{NULL, 0, 0, 0},
	};

	while (1) {
		int c;
		int option_index = 0;

		c = getopt_long(argc, argv, "vir",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'i':
			what |= 1;
			break;

		case 'r':
			what |= 2;
			break;

		case 'v':
			verbose = 1;
			break;

		case 0:
			break;

		default:
			fprintf(stderr, "invalid option\n");
			usage();
			exit(1);
		}
	}

	if (argc - optind != 1) {
		usage();
		exit(1);
	}

	switch (what) {
	case 1:
		if (!(verbose_flag & FLAG_NO_SIGN))
			if (validate_ipkg(argv[optind]) != 0)
				exit(1);
		install_ipkg(argv[optind], verbose);
		break;

	case 2:
		remove_ipkg(argv[optind], verbose);
		break;

	default:
		fprintf(stderr, "invalid option\n");
		usage();
		exit(1);
	}
}
