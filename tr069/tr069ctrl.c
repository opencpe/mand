#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#include <sys/time.h>
#include <event.h>

#include "tr069ctrl.h"

#include "libdmconfig/dmconfig.h"

static void usage(void);

int			stype = AF_INET;

CTRL_COMMAND		command = TR069CTRL_UNDEF;

char			*what = "";

#define RETRY_CONN_DELAY 10 /* in seconds */

static struct timeval	timeout = {	/* custom libdmconfig session timeout */
	.tv_sec = 30,
	.tv_usec = 0
};

#define chomp(s) ({ \
        char *c = (s) + strlen((s)) - 1; \
        while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
                *c-- = '\0'; \
        s; \
})

static void usage(void)
{
    printf("Usage: tr069ctrl [options] command [arguments]\n"
    	   "\n"
	   "options:\n"
	   "  -s <path>         Path to the socket [obsolete and has no effect anymore]\n"
	   "  -c inet|unix      either try to communicate with a TCP/IP socket (inet) or a local unix socket (unix) (default is unix)\n"
	   "  -h                Print usage\n"
	   "\n"
	   "commands:\n"
	   "  bootstrap         Send a TR069 bootstrap to current ACS\n"
	   "\n");
}

extern int optind;

void parse_commandline(int argc, char **argv)
{
    int c;

    while (-1 != (c = getopt(argc, argv, "c:s:h"))) {
        switch(c) {
            case 'h':
                usage();
                exit(EXCODE_USAGE);
                break;

            case 's':		/* dummy: left only for compatibility reasons */
                break;

	    case 'c':
	    	if (!strcmp(optarg, "inet"))
			stype = AF_INET;
		else if (!strcmp(optarg, "unix"))
			stype = AF_UNIX;
		else {
			usage();
			exit(EXCODE_USAGE);
		}
		break;

            default:
                usage();
                exit(EXCODE_USAGE);
                break;
        }
    }

    if ((argc - optind) <= 0) {
	    usage();
	    exit(EXCODE_USAGE);
    }

    if (strcasecmp(*(argv + optind), "commit") == 0) {
	    command = TR069CTRL_COMMIT;
    } else if (strcasecmp(*(argv + optind), "get") == 0) {
	    command = TR069CTRL_GET;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "set") == 0) {
	    command = TR069CTRL_SET;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "add") == 0) {
	    command = TR069CTRL_ADD;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "del") == 0) {
	    command = TR069CTRL_DEL;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "dump") == 0) {
	    command = TR069CTRL_DUMP;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "saveconfig") == 0) {
	    command = TR069CTRL_CONFSAVE;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "restoreconfig") == 0) {
	    command = TR069CTRL_CONFRESTORE;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    }
    if (command == TR069CTRL_UNDEF) {
	    fprintf(stderr, "tr069ctrl: Error: Invalid command \"%s\"\n", *argv);
	    usage();
	    exit(EXCODE_USAGE);
    }
}

int tr069ctrl(int argc, char **argv)
{
	uint32_t		rc;
	DMCONTEXT		ctx;
	DIAM_AVPGRP		*grp;
	DIAM_AVPGRP		*ret_grp;

	struct event_base	*base;

	parse_commandline(argc, argv);

	if (!(base = event_init()))
		return EXCODE_FAILURE;

	dm_context_init(&ctx, base);

	if (dm_init_socket(&ctx, stype))
		goto abort;

	if (dm_send_start_session(&ctx, CMD_FLAG_READWRITE, &timeout, NULL))
		goto abort;

	switch(command) {
		case TR069CTRL_DUMP: {
			char *dump;

			if (dm_send_cmd_dump(&ctx, what, &dump))
				goto abort;
			printf("%s", dump);
			free(dump);

			break;
		}
		case TR069CTRL_GET: {
			uint32_t	type, vendor_id;
			uint8_t		flags;
			void		*data;
			size_t		len;

			char		*result;

			if (!(grp = dm_grp_new()))
				goto abort;
			if (dm_grp_get_unknown(&grp, what) ||
			    dm_send_packet_get(&ctx, grp, &ret_grp) ||
			    diam_avpgrp_get_avp(ret_grp, &type, &flags, &vendor_id,
	     			  		&data, &len) ||
			    dm_decode_unknown_as_string(type, data, len, &result)) {
				dm_grp_free(grp);
				goto abort;
			}
			printf("%s", result);
			free(result);

			dm_grp_free(grp);

			break;
		}
		case TR069CTRL_SET: {
			char *p;

			if (!(grp = dm_grp_new()))
				goto abort;
			if ((p = strchr(what, '=')))
				*p++ = '\0';
			if (dm_grp_set_unknown(&grp, what, p ? : "") ||
			    dm_send_packet_set(&ctx, grp)) {
				dm_grp_free(grp);
				goto abort;
			}
			dm_grp_free(grp);

			break;
		}
		case TR069CTRL_ADD: {
			uint16_t instance = DM_ADD_INSTANCE_AUTO;

			if (dm_send_add_instance(&ctx, what, &instance) == 0) {
				printf("new instance: %s.%u\n", what, instance);
			} else
				printf("failed\n");
			break;
		}
		case TR069CTRL_DEL:
			if (dm_send_del_instance(&ctx, what) == 0) {
				printf("success\n");
			} else
				printf("failed\n");
			break;
		case TR069CTRL_COMMIT:	/* backwards compatibility */
			if (dm_send_save(&ctx))
				goto abort;
			break;
		case TR069CTRL_CONFSAVE:
			if (dm_send_cmd_conf_save(&ctx, what))
				goto abort;
			break;
		case TR069CTRL_CONFRESTORE:
			if (dm_send_cmd_conf_restore(&ctx, what))
				goto abort;
			break;

		default:
			/* XXX NEVER REACHED */
			fprintf(stderr, "Oops\n");
			goto abort;
	}

	rc = dm_send_end_session(&ctx);

	dm_shutdown_socket(&ctx);
	event_base_free(base);

	return rc ? EXCODE_FAILURE : EXCODE_SUCCESS;

abort:

	if (dm_context_get_sessionid(&ctx))
		dm_send_end_session(&ctx);
	dm_shutdown_socket(&ctx);
	event_base_free(base);

	return EXCODE_FAILURE;
}

int main(int argc, char **argv)
{
	char *progname;
	int ret = 0;

	progname = basename(argv[0]);

	openlog(progname, LOG_CONS | LOG_PID, LOG_DAEMON);

	if (strncmp(progname, "lt-", 3) == 0)
		progname += 3;

	if (strcmp(progname, "tr069ctrl") == 0)
		ret = tr069ctrl(argc, argv);

	closelog();

	return ret;
}
