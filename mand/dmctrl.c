/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
#include <ev.h>

#include "dmctrl.h"

#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dm_dmconfig_rpc_stub.h"
#include "libdmconfig/dm_dmclient_rpc_impl.h"

static void usage(void);

int			stype = AF_INET;

CTRL_COMMAND		command = DMCTRL_UNDEF;

char			*base = "";
char			*what = "";

#define RETRY_CONN_DELAY 10 /* in seconds */

#define chomp(s) ({ \
        char *c = (s) + strlen((s)) - 1; \
        while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
                *c-- = '\0'; \
        s; \
})

static void usage(void)
{
    printf("Usage: dmctrl [options] command [arguments]\n"
    	   "\n"
	   "options:\n"
	   "  -s <path>         Path to the socket [obsolete and has no effect anymore]\n"
	   "  -c inet|unix      either try to communicate with a TCP/IP socket (inet) or a local unix socket (unix) (default is unix)\n"
	   "  -h                Print usage\n"
	   "\n"
	   "commands:\n"
	   "  bootstrap         Send a DM bootstrap to current ACS\n"
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
	    command = DMCTRL_COMMIT;
    } else if (strcasecmp(*(argv + optind), "get") == 0) {
	    command = DMCTRL_GET;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "set") == 0) {
	    command = DMCTRL_SET;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "add") == 0) {
	    command = DMCTRL_ADD;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "del") == 0) {
	    command = DMCTRL_DEL;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "find") == 0) {
	    command = DMCTRL_FIND;
	    base = *(argv + optind + 1);
	    what = *(argv + optind + 2);
    } else if (strcasecmp(*(argv + optind), "dump") == 0) {
	    command = DMCTRL_DUMP;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "saveconfig") == 0) {
	    command = DMCTRL_CONFSAVE;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "restoreconfig") == 0) {
	    command = DMCTRL_CONFRESTORE;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "restart") == 0) {
	    command = DMCTRL_RESTART;
    } else if (strcasecmp(*(argv + optind), "shutdown") == 0) {
	    command = DMCTRL_SHUTDOWN;
    }
    if (command == DMCTRL_UNDEF) {
	    fprintf(stderr, "dmctrl: Error: Invalid command \"%s\"\n", *argv);
	    usage();
	    exit(EXCODE_USAGE);
    }
}

uint32_t dmctrl_connect_cb(DMCONFIG_EVENT event, DMCONTEXT *socket, void *userdata __attribute__((unused)))
{
	uint32_t rc;
	DM2_AVPGRP *answer;

	if (event != DMCONFIG_CONNECTED)
		return RC_OK;

	if (!(answer = talloc_zero(socket, DM2_AVPGRP)))
		return RC_ERR_ALLOC;

	if ((rc = rpc_startsession(socket, CMD_FLAG_READWRITE, 10, answer)) != RC_OK) {
		ev_break(socket->ev, EVBREAK_ONE);

		return rc;
	}

	switch(command) {
		case DMCTRL_DUMP: {
			char *dump;

			if ((rpc_db_dump(socket, what, answer) != RC_OK)
			    || dm_expect_string_type(answer, AVP_STRING, VP_TRAVELPING, &dump) != RC_OK)
				break;

			printf("%s", dump);
			talloc_free(dump);

			break;
		}
		case DMCTRL_GET: {
			uint32_t code;
			uint32_t vendor_id;
			void *data;
			size_t size;
			char *result;

			if ((rc = rpc_db_get(socket, 1, (const char **)&what, answer)) != RC_OK) {
				printf("failed with rc=%d (0x%08x)\n", rc, rc);
				break;
			}

			if (dm_expect_avp(answer, &code, &vendor_id, &data, &size) != RC_OK
			    || vendor_id != VP_TRAVELPING
			    || dm_expect_group_end(answer) != RC_OK
			    || dm_decode_unknown_as_string(code, data, size, &result) != RC_OK)
				break;

			printf("%s", result);
			free(result);

			break;
		}

		case DMCTRL_SET: {
			char *p;
			struct rpc_db_set_path_value set_value = {
				.path  = what,
				.value = {
					.code = AVP_UNKNOWN,
					.vendor_id = VP_TRAVELPING,
				},
			};

			if ((p = strchr(what, '=')))
				*p++ = '\0';

			set_value.value.data = p ? : "";
			set_value.value.size = strlen(set_value.value.data);

			if ((rc = rpc_db_set(socket, 1, &set_value, answer)) != RC_OK) {
				printf("failed with rc=%d (0x%08x)\n", rc, rc);
				break;
			}

			break;
		}
		case DMCTRL_ADD: {
			uint16_t instance = DM_ADD_INSTANCE_AUTO;

			if (rpc_db_addinstance(socket, what, instance, answer) == RC_OK &&
			    dm_expect_uint16_type(answer, AVP_UINT16, VP_TRAVELPING, &instance) == RC_OK) {
				printf("new instance: %s.%u\n", what, instance);
			} else
				printf("failed\n");

			break;
		}
		case DMCTRL_DEL:
			if (rpc_db_delinstance(socket, what, answer) == RC_OK) {
				printf("success\n");
			} else
				printf("failed\n");
			break;

		case DMCTRL_FIND: {
			char *p;
			struct dm2_avp search = {
				.code = AVP_UNKNOWN,
				.vendor_id = VP_TRAVELPING,
			};
			uint16_t instance = 0;

			if ((p = strchr(what, '=')))
				*p++ = '\0';

			search.data = p ? : "";
			search.size = strlen(search.data);

			if ((rc = rpc_db_findinstance(socket, base, what, &search, answer)) != RC_OK) {
				fprintf(stderr, "couldn't get instance\n");
				break;
			}

			if ((rc = dm_expect_uint16_type(answer, AVP_UINT16, VP_TRAVELPING, &instance)) != RC_OK) {
				fprintf(stderr, "couldn't get instance\n");
				break;
			}
			printf("Instance: %d, Path: %s.%d\n", instance, base, instance);

			break;
		}
		case DMCTRL_COMMIT:
			if (rpc_db_commit(socket, answer) == RC_OK) {
				printf("success\n");
			} else
				printf("failed\n");
			break;

		case DMCTRL_SHUTDOWN:
			if (rpc_system_shutdown(socket) == RC_OK) {
				printf("success\n");
			} else
				printf("failed\n");
			break;

		case DMCTRL_RESTART:
			if (rpc_system_restart(socket) == RC_OK) {
				printf("success\n");
			} else
				printf("failed\n");
			break;

		default:
			/* XXX NEVER REACHED */
			fprintf(stderr, "Oops\n");
			break;
	}

	rpc_endsession(socket);

	ev_break(socket->ev, EVBREAK_ONE);

	return  RC_OK;
}

int dmctrl(int argc, char **argv)
{
	struct ev_loop *loop = EV_DEFAULT;
	uint32_t rc;
	DMCONTEXT *ctx;

	parse_commandline(argc, argv);

	if (!(ctx = dm_context_new()))
		return RC_ERR_ALLOC;

	dm_context_init(ctx, loop, stype, NULL, dmctrl_connect_cb, NULL);

	/* connect */
	if ((rc = dm_connect_async(ctx)) != RC_OK)
		goto abort;

	ev_run(loop, 0);

 abort:
	dm_context_shutdown(ctx, DMCONFIG_ERROR_CONNECTING);
	dm_context_release(ctx);
	ev_loop_destroy(loop);

	return rc;
}

int main(int argc, char **argv)
{
	char *progname;
	int ret = 0;

	progname = basename(argv[0]);

	openlog(progname, LOG_CONS | LOG_PID, LOG_DAEMON);

	if (strncmp(progname, "lt-", 3) == 0)
		progname += 3;

	if (strcmp(progname, "dmctrl") == 0)
		ret = dmctrl(argc, argv);

	closelog();

	return ret;
}
