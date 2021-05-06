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
int			array_f = 0;

#define RETRY_CONN_DELAY 10 /* in seconds */

#define chomp(s) ({ \
        char *c = (s) + strlen((s)) - 1; \
        while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
                *c-- = '\0'; \
        s; \
})

typedef void (*DECODE_CB)(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data);

uint32_t
decode_node_list(const char *prefix, DM2_AVPGRP *grp, DECODE_CB cb, void *cb_data)
{
	uint32_t r;
	DM2_AVPGRP container;
	uint32_t code;
	uint32_t vendor_id;
	void *data;
	size_t size;

	char *name, *path;
	uint16_t id;
	uint32_t type;

	if ((r = dm_expect_avp(grp, &code, &vendor_id, &data, &size)) != RC_OK)
		return r;

	if (vendor_id != VP_TRAVELPING)
		return RC_ERR_MISC;

	dm_init_avpgrp(grp->ctx, data, size, &container);

	switch (code) {
	case AVP_TABLE:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_INSTANCE:
		if ((r = dm_expect_uint16_type(&container, AVP_NAME, VP_TRAVELPING, &id)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%d", prefix, id)))
			return RC_ERR_ALLOC;

		while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_OBJECT:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_ELEMENT:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
		    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
			return r;

		cb(path, code, vendor_id, data, size, cb_data);
		break;

	case AVP_ARRAY:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
		    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (dm_expect_group_end(&container) != RC_OK) {
			if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
				return r;
			cb(path, code, vendor_id, data, size, cb_data);
		}
		break;

	default:
		return RC_ERR_MISC;
	}

	return RC_OK;
}

void list_cb(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data __attribute__((unused)))
{
	printf("%08x:%08x: %s, %zd, %p\n", vendor_id, code, name, size, data);
}

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

    while (-1 != (c = getopt(argc, argv, "ac:s:h"))) {
        switch(c) {
            case 'h':
                usage();
                exit(EXCODE_USAGE);
                break;

            case 's':		/* dummy: left only for compatibility reasons */
                break;

	    case 'a':
		array_f = 1;
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
    } else if (strcasecmp(*(argv + optind), "list") == 0) {
	    command = DMCTRL_LIST;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "get") == 0) {
	    command = DMCTRL_GET;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "set") == 0) {
	    command = DMCTRL_SET;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "add") == 0) {
	    command = DMCTRL_ADD;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "del") == 0) {
	    command = DMCTRL_DEL;
	    what = optind+1 == argc ? "" : *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "find") == 0) {
	    command = DMCTRL_FIND;
	    base = optind+1 == argc ? "" : *(argv + optind + 1);
	    what = optind+1 == argc ? "" : *(argv + optind + 2);
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

	if (!(answer = dm_new_avpgrp(socket)))
		return RC_ERR_ALLOC;

	if ((rc = rpc_startsession(socket, CMD_FLAG_READWRITE, 10, answer)) != RC_OK) {
		ev_break(socket->ev, EVBREAK_ONE);
		dm_free_avpgrp(answer);

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
		case DMCTRL_LIST: {
			if ((rc = rpc_db_list(socket, 0, what, answer)) != RC_OK) {
				printf("failed with rc=%d (0x%08x)\n", rc, rc);
				break;
			}

			while (decode_node_list("", answer, list_cb, NULL) == RC_OK) {
			}

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
			    || dm_expect_group_end(answer) != RC_OK)
				break;

			if (vendor_id == VP_TRAVELPING && code == AVP_ARRAY) {
				DM2_AVPGRP container;

				dm_init_avpgrp(answer->ctx, data, size, &container);

				while (dm_expect_group_end(&container) != RC_OK) {
					if (dm_expect_avp(&container, &code, &vendor_id, &data, &size) != RC_OK
					    || dm_decode_unknown_as_string(code, data, size, &result) != RC_OK)
						break;

					printf("%s\n", result);
					free(result);
				}
			} else {
				if (dm_decode_unknown_as_string(code, data, size, &result) != RC_OK)
					break;

				printf("%s\n", result);
				free(result);
			}

			break;
		}

		case DMCTRL_SET:
			if (array_f) {
				char *p, *s;
				int i, cnt;
				char *saveptr;

				struct rpc_db_set_path_value set_array = {
					.path  = what,
					.value = {
						.code = AVP_ARRAY,
						.vendor_id = VP_TRAVELPING,
					},
				};
				struct rpc_db_set_path_value *array;

				if ((p = strchr(what, '=')))
					*p++ = '\0';

				cnt = (*p) ? 1 : 0;
				for (s = p; *s; s++)
					if (*s == ',')
						cnt++;

				if (!(array = calloc(cnt, sizeof(struct rpc_db_set_path_value))))
					break;
				set_array.value.data = array;
				set_array.value.size = cnt;

				s = strtok_r(p, ",", &saveptr);
				for (i = 0; i < cnt && s; i++) {
					printf("array[%d]=%s\n", i, s);

					array[i].value.code = AVP_UNKNOWN;
					array[i].value.vendor_id = VP_TRAVELPING;
					array[i].value.data = s;
					array[i].value.size = strlen(s);

					s = strtok_r(NULL, ",", &saveptr);
				}

				if ((rc = rpc_db_set(socket, 1, &set_array, answer)) != RC_OK) {
					printf("failed with rc=%d (0x%08x)\n", rc, rc);
					free(array);
					break;
				}
				printf("success with rc=%d (0x%08x)\n", rc, rc);
				free(array);

			} else {
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
			}
			break;

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
			if (rpc_db_save(socket, answer) == RC_OK) {
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
	dm_free_avpgrp(answer);

	rpc_endsession(socket);

	ev_break(socket->ev, EVBREAK_ONE);

	return  RC_OK;
}

int dmctrl(int argc, char **argv)
{
	uint32_t rc;
	DMCONTEXT *ctx;

	parse_commandline(argc, argv);

	if (!(ctx = dm_context_new()))
		return RC_ERR_ALLOC;

	dm_context_init(ctx, EV_DEFAULT_ stype, NULL, dmctrl_connect_cb, NULL);

	/* connect */
	if ((rc = dm_connect_async(ctx)) != RC_OK)
		goto abort;

	ev_run(EV_DEFAULT_ 0);

 abort:
	dm_context_shutdown(ctx, DMCONFIG_ERROR_CONNECTING);
	dm_context_release(ctx);
	ev_loop_destroy(EV_DEFAULT);

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
