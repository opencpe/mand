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

    if (strcasecmp(*(argv + optind), "bootstrap") == 0) {
	    command = TR069CTRL_BOOTSTRAP;
    } else if (strcasecmp(*(argv + optind), "commit") == 0) {
	    command = TR069CTRL_COMMIT;
    } else if (strcasecmp(*(argv + optind), "getdevice") == 0) {
	    command = TR069CTRL_GETDEVICE;
	    what = *(argv + optind + 1);
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
    } else if (strcasecmp(*(argv + optind), "newclient") == 0) {
	    command = TR069CTRL_NEWCLIENT;
    } else if (strcasecmp(*(argv + optind), "delclient") == 0) {
	    command = TR069CTRL_DELCLIENT;
    } else if (strcasecmp(*(argv + optind), "reqaccess") == 0) {
	    command = TR069CTRL_REQACC;
    } else if (strcasecmp(*(argv + optind), "setaccess") == 0) {
	    command = TR069CTRL_SETACC;

    } else if (strcasecmp(*(argv + optind), "wanup") == 0) {
	    command = TR069CTRL_WANUP;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "wandown") == 0) {
	    command = TR069CTRL_WANDOWN;
	    what = *(argv + optind + 1);
    } else if (strcasecmp(*(argv + optind), "sysup") == 0) {
	    command = TR069CTRL_SYSUP;
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
		case TR069CTRL_NEWCLIENT: {
			DIAM_AVPGRP     *grp;
			uint32_t        rc;

			if(!(grp = dm_grp_new()))
				return RC_ERR_ALLOC;

			optind++;
			fprintf(stderr, "ind: %d, argc: %d\n", optind, argc);
			if (optind < argc) {
				struct in_addr addr;

				inet_pton(AF_INET, argv[optind], &addr);
				diam_avpgrp_add_address(NULL, &grp, AVP_GW_IPADDRESS, 0, VP_TRAVELPING, AF_INET, &addr);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_MACADDRESS, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_USERNAME, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_PASSWORD, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_USERAGENT, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}

			rc = dm_generic_send_request(&ctx, CMD_GW_NEW_CLIENT, grp, NULL);
			dm_grp_free(grp);
			if(rc)
				goto abort;

			break;
		}
		case TR069CTRL_DELCLIENT: {
			DIAM_AVPGRP     *grp;
			uint32_t        rc;

			if(!(grp = dm_grp_new()))
				return RC_ERR_ALLOC;

			optind++;
			if (optind < argc) {
				struct in_addr addr;

				inet_pton(AF_INET, argv[optind], &addr);
				diam_avpgrp_add_address(NULL, &grp, AVP_GW_IPADDRESS, 0, VP_TRAVELPING, AF_INET, &addr);
				optind++;
			}
			rc = dm_generic_send_request(&ctx, CMD_GW_DEL_CLIENT, grp, NULL);
			dm_grp_free(grp);
			if(rc)
				goto abort;

			break;
		}
		case TR069CTRL_REQACC: {
			DIAM_AVPGRP     *grp;
			uint32_t        rc;

			if(!(grp = dm_grp_new()))
				return RC_ERR_ALLOC;

			optind++;
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_OBJ_ID, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_USERNAME, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_PASSWORD, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_ACCESSCLASS, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_USERAGENT, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			rc = dm_generic_send_request(&ctx, CMD_GW_CLIENT_REQ_ACCESSCLASS, grp, NULL);
			dm_grp_free(grp);
			if(rc)
				goto abort;

			break;
		}
		case TR069CTRL_SETACC: {
			DIAM_AVPGRP	*grp;
			uint32_t	rc;

			if(!(grp = dm_grp_new()))
				return RC_ERR_ALLOC;

			optind++;
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_OBJ_ID, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind + 1 < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_USERNAME, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			if (optind < argc) {
				diam_avpgrp_add_string(NULL, &grp, AVP_GW_ACCESSCLASS, 0, VP_TRAVELPING, argv[optind]);
				optind++;
			}
			rc = dm_generic_send_request(&ctx, CMD_GW_CLIENT_SET_ACCESSCLASS, grp, NULL);
			dm_grp_free(grp);
			if(rc)
				goto abort;

			break;
		}
		case TR069CTRL_GETDEVICE: {
			char *device;

			if (dm_send_cmd_getdevice(&ctx, what, &device))
				goto abort;
			printf("%s", device);
			free(device);

			break;
		}
		case TR069CTRL_WANUP:
			if (dm_send_cmd_wanup(&ctx))
				goto abort;
			break;
		case TR069CTRL_WANDOWN:
			if (dm_send_cmd_wandown(&ctx))
				goto abort;
			break;
		case TR069CTRL_SYSUP:
			if (dm_send_cmd_sysup(&ctx))
				goto abort;
			break;
		case TR069CTRL_DUMP: {
			char *dump;

			if (dm_send_cmd_dump(&ctx, what, &dump))
				goto abort;
			printf("%s", dump);
			free(dump);

			break;
		}
		case TR069CTRL_BOOTSTRAP:
			if (dm_send_cmd_bootstrap(&ctx))
				goto abort;
			break;
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

const char *ppp_env[] = {
	"PROTO",
	"DEVICE",
	"IFNAME",
	"IPLOCAL",
	"IPREMOTE",
	"PEERNAME",
	"SPEED",
	"CONNECT_TIME",
	"BYTES_SENT",
	"BYTES_RCVD",
	"LINKNAME",
	"CALL_FILE",
	"DNS1",
	"DNS2",
	NULL
};

int hotplug(int argc, char **argv)
{
	const char *action = getenv("ACTION");
	const char *iface  = getenv("INTERFACE");
	const char *proto  = getenv("PROTO");
	const char *seqnum = getenv("SEQNUM");
#ifdef WITH_UDEV
	const char *device;
	const char *dpath   = getenv("DEVPATH");
#endif

	char buf[1024];

	dmconfig_debug_level = 0;

	fprintf(stderr, "hotplug(%d): %s, %s, %s, seqnum: %s\n", argc, argv[1], action, iface, seqnum ? seqnum : "NULL");
#ifdef WITH_UDEV
	syslog(LOG_INFO, "%d, %s, %s, %s, %s", argc, argv[1], action, iface, dpath);
#else
	syslog(LOG_INFO, "%d, %s, %s, %s", argc, argv[1], action, iface);
#endif
	if (proto)
		syslog(LOG_INFO, "proto: %s", proto);

	if (argc != 2)
		return 1;

#ifdef WITH_UDEV
	if (!dpath)
		goto udev_out;

	/*
	 * minimum udev implementation
	 */
	device = strrchr(dpath, '/') + 1;
	syslog(LOG_INFO, "device: %s", device);
	if (!strcmp(action, "add")) {
		FILE *f;
		int r, major, minor, type;

		if ((strstr(dpath, "/block/") != NULL) ||
		    (strstr(dpath, "mtdblock") != NULL))
			type = S_IFBLK;
		else
			type = S_IFCHR;

		snprintf(buf, sizeof(buf), "/sys%s/dev", dpath);

		f = fopen(buf, "r");
		if (!f)
			goto udev_out;

		r = fscanf(f, "%d:%d", &major, &minor);
		fclose(f);

		if (r != 2) {
			syslog(LOG_ERR, "fscanf returned %d", r);
			goto udev_out;
		}

		snprintf(buf, sizeof(buf), "/dev/%s", device);
		umask(0);
		mknod(buf, 0660 | type, makedev(major, minor));
		syslog(LOG_INFO, "making device: %s", buf);
	} else if (!strcmp(action, "remove")) {
		snprintf(buf, sizeof(buf), "/dev/%s", device);
		unlink(buf);
		syslog(LOG_INFO, "removed device: %s", buf);
	}
 udev_out:

#endif

	if (strcasecmp("net", argv[1]) == 0) {
		if (action && iface) {
			DMCONTEXT		ctx;
			uint32_t		rc;
			int			l;

			struct event_base	*base;

			l = snprintf(buf, sizeof(buf), "%s %s %s", argv[1], action, iface);

			if (strcasecmp("ipup", action) != 0 &&
			    strcasecmp("ipdown", action) != 0) {
				/* only ipup and ipdown is handled by this anymore... */
				syslog(LOG_INFO, "let uevent handle this...");
				return 0;
			}

			if (proto &&
			    (strcasecmp("ipup", action) == 0 ||
			     strcasecmp("ipdown", action) == 0)) {

				const char *link = getenv("LINK");

				if (!link || !*link)
					link = "-";

				l += snprintf(buf + l, sizeof(buf) - 1 - l, " %s %s", link, proto);
			}
			l += snprintf(buf + l, sizeof(buf) - l, CRLF CRLF);

			if (!(base = event_init())) {
				syslog(LOG_ERR, "event_init failed");
				return EXCODE_FAILURE;
			}

			dm_context_init(&ctx, base);

			rc = dm_init_socket(&ctx, stype);
			while (rc == RC_ERR_CONNECTION) {
				syslog(LOG_WARNING, "dm_init_socket failed (code = %d), retrying in %us", rc, RETRY_CONN_DELAY);
				sleep(RETRY_CONN_DELAY);
				rc = dm_init_socket(&ctx, stype);
			}
			if (rc) {
				event_base_free(base);
				syslog(LOG_ERR, "dm_init_socket failed (code = %d)", rc);
				return EXCODE_FAILURE;
			}

			if ((rc = dm_send_start_session(&ctx, CMD_FLAG_READWRITE, &timeout, NULL))) {
				dm_shutdown_socket(&ctx);
				event_base_free(base);
				syslog(LOG_ERR, "dm_send_start_session failed (code = %d)", rc);
				return EXCODE_FAILURE;
			}

			syslog(LOG_INFO, "sending: dm_send_cmd_hotplug %s", buf);

			if ((rc = dm_send_cmd_hotplug(&ctx, buf))) {
				dm_send_end_session(&ctx);
				dm_shutdown_socket(&ctx);
				event_base_free(base);
				syslog(LOG_ERR, "dm_send_cmd_hotplug failed (code = %d)", rc);
				return EXCODE_FAILURE;
			}

			if ((rc = dm_send_end_session(&ctx))) {
				dm_shutdown_socket(&ctx);
				event_base_free(base);
				syslog(LOG_ERR, "dm_send_end_session failed (code = %d)", rc);
				return EXCODE_FAILURE;
			}
			dm_shutdown_socket(&ctx);
			event_base_free(base);
		}
	}

	syslog(LOG_INFO, "exit");
	return 0;
}

#if defined(WITH_DHCP_DHCPD)

int dhcpinfo(int argc, char **argv)
{
	DMCONTEXT		ctx;
	uint32_t		rc;

	struct event_base	*base;

	dmconfig_debug_level = 0;

	if (argc > 1) {
		if (!(base = event_init())) {
			syslog(LOG_ERR, "event_init failed (%d)", rc);
			return EXCODE_FAILURE;
		}

		dm_context_init(&ctx, base);

		if ((rc = dm_init_socket(&ctx, stype))) {
			event_base_free(base);
			syslog(LOG_ERR, "dm_init_socket failed (code = %d)", rc);
			return EXCODE_FAILURE;
		}

		if ((rc = dm_send_start_session(&ctx, CMD_FLAG_READWRITE, &timeout, NULL))) {
			dm_shutdown_socket(&ctx);
			event_base_free(base);
			syslog(LOG_ERR, "dm_send_start_session failed (code = %d)", rc);
			return EXCODE_FAILURE;
		}

		syslog(LOG_INFO, "sending: dm_send_cmd_dhcpinfo %s", argv[1]);

		if ((rc = dm_send_cmd_dhcpinfo(&ctx, argv[1]))) {
			dm_send_end_session(&ctx);
			dm_shutdown_socket(&ctx);
			event_base_free(base);
			syslog(LOG_ERR, "dm_send_cmd_dhcpinfo failed (code = %d)", rc);
			return EXCODE_FAILURE;
		}

		if ((rc = dm_send_end_session(&ctx))) {
			dm_shutdown_socket(&ctx);
			event_base_free(base);
			syslog(LOG_ERR, "dm_send_end_session failed (code = %d)", rc);
			return EXCODE_FAILURE;
		}
		dm_shutdown_socket(&ctx);
		event_base_free(base);
	}
	return EXCODE_SUCCESS;
}

#endif

#if defined(WITH_DHCP_ISC)

int dhcpnotify(int argc, char **argv)
{
	DMCONTEXT		ctx;
	uint32_t		rc;
	DIAM_AVPGRP             *grp;

	uint32_t		ev = 0;
	struct in_addr		addr;

	struct event_base	*base;

	dmconfig_debug_level = 0;

	if (argc < 4)
		return EXCODE_FAILURE;

	if(!(grp = dm_grp_new()))
		return EXCODE_FAILURE;

	if (strcasecmp(argv[1], "commit") == 0) {
		ev = CMD_DHCP_CLIENT_ACK;
	} else if (strcasecmp(argv[1], "release") == 0) {
		ev = CMD_DHCP_CLIENT_RELEASE;
	} else if (strcasecmp(argv[1], "expire") == 0) {
		ev = CMD_DHCP_CLIENT_EXPIRE;
	} else
		return EXCODE_FAILURE;

	if (inet_pton(AF_INET, argv[2], &addr) <= 0) {
		perror("inet_pton");
		return EXCODE_FAILURE;
	}

	diam_avpgrp_add_address(NULL, &grp, AVP_DHCP_IPADDRESS, 0, VP_TRAVELPING, AF_INET, &addr);
	diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_MACADDRESS, 0, VP_TRAVELPING, argv[3]);
	if (argc >= 5)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_REMOTE_ID, 0, VP_TRAVELPING, argv[4]);
	if (argc >= 6)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_CIRCUIT_ID, 0, VP_TRAVELPING, argv[5]);

	if (!(base = event_init())) {
		syslog(LOG_ERR, "event_init failed", rc);
		return EXCODE_FAILURE;
	}

	dm_context_init(&ctx, base);

	if ((rc = dm_init_socket(&ctx, stype))) {
		event_base_free(base);
		syslog(LOG_ERR, "dm_init_socket failed (code = %d)", rc);
		return EXCODE_FAILURE;
	}

	if ((rc = dm_send_start_session(&ctx, CMD_FLAG_READWRITE, &timeout, NULL))) {
		dm_shutdown_socket(&ctx);
		event_base_free(base);
		syslog(LOG_ERR, "dm_send_start_session failed (code = %d)", rc);
		return EXCODE_FAILURE;
	}

	syslog(LOG_INFO, "sending: dm_send_cmd_dhcpinfo %s", argv[1]);

        rc = dm_generic_send_request(&ctx, ev, grp, NULL);
        dm_grp_free(grp);

	if (rc)
		syslog(LOG_ERR, "dm_send_cmd_dhcpinfo failed (code = %d)", rc);

	if ((rc = dm_send_end_session(&ctx))) {
		dm_shutdown_socket(&ctx);
		event_base_free(base);
		syslog(LOG_ERR, "dm_send_end_session failed (code = %d)", rc);
		return EXCODE_FAILURE;
	}
	dm_shutdown_socket(&ctx);
	event_base_free(base);

	return EXCODE_SUCCESS;
}
#endif

#if defined(WITH_DHCP_DNSMASQ)

static unsigned char hexchar(const char c)
{
	switch (c) {
	case '0' ... '9':
		return c - '0';

	case 'A' ... 'F':
		return c - 'A' + 10;

	case 'a' ... 'f':
		return c - 'a' + 10;
	}
	return 0;
}

static unsigned char hex2bin(const char *s)
{
	return (hexchar(*s) << 4) + hexchar(*(s + 1));
}

int dnsmasqnotify(int argc, char **argv)
{
	const char *iface = getenv("DNSMASQ_INTERFACE");
	const char *clientid = getenv("DNSMASQ_CLIENT_ID");
	const char *expires = getenv("DNSMASQ_LEASE_EXPIRES");
	const char *agentid = getenv("DNSMASQ_AGENT_ID");
	const char *optlist = getenv("DNSMASQ_OPTLIST");
	const char *optreqlist = getenv("DNSMASQ_OPTREQLIST");

	DMCONTEXT		ctx;
	uint32_t		rc;
	DIAM_AVPGRP             *grp;

	uint32_t ev = 0;
	struct in_addr addr;

	struct event_base	*base;
	time_t lexpire = 0;

	dmconfig_debug_level = 0;

	syslog(LOG_ERR, "%s: action: '%s'", __FUNCTION__, argv[1]);
	if (strcasecmp(argv[1], "init") == 0) {
		/* TODO: init is special, do that later .... */
		return 0;
	}

	syslog(LOG_ERR, "%s: argc: %d", __FUNCTION__, argc);
	if (argc < 4)
		return EXCODE_FAILURE;

	if (!(grp = dm_grp_new())) {
		syslog(LOG_ERR, "%s: dm_grp_new() failed", __FUNCTION__);
		return EXCODE_FAILURE;
	}

	if (strcasecmp(argv[1], "add") == 0 || strcasecmp(argv[1], "old") == 0) {
		ev = CMD_DHCP_CLIENT_ACK;
	} else if (strcasecmp(argv[1], "del") == 0) {
		ev = CMD_DHCP_CLIENT_RELEASE;
	} else
		return EXCODE_FAILURE;

	if (inet_pton(AF_INET, argv[3], &addr) <= 0) {
		syslog(LOG_ERR, "%s: can't convert %s (%m)", __FUNCTION__, argv[3]);
		perror("inet_pton");
		return EXCODE_FAILURE;
	}

	if (expires)
		lexpire = strtol(expires, NULL, 10);

	diam_avpgrp_add_address(NULL, &grp, AVP_DHCP_IPADDRESS, 0, VP_TRAVELPING, AF_INET, &addr);
	diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_MACADDRESS, 0, VP_TRAVELPING, argv[2]);
	if (argc > 4)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_HOSTNAME, 0, VP_TRAVELPING, argv[4]);

	if (lexpire != 0)
		diam_avpgrp_add_uint32(NULL, &grp, AVP_DHCP_EXPIRE, 0, VP_TRAVELPING, lexpire);

	if (clientid)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_CLIENT_ID, 0, VP_TRAVELPING, clientid);

	if (iface)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_INTERFACE, 0, VP_TRAVELPING, iface);

	syslog(LOG_ERR, "%s, ID: %s, IF: %s IP: %s, MAC: %s, Host: %s, expires: %s (%d), agent_id: %s",
	       argv[1],
	       clientid ? clientid : "NULL",
	       iface ? iface : "NULL",
	       argv[3],
	       argv[2],
	       (argc > 4) ? argv[4] : "NULL",
	       expires ? expires : "NULL",
	       lexpire - time(NULL),
	       agentid ? agentid : "NULL");

	if (agentid) {
		char *id = agentid;

		while (*id) {
			unsigned char opt = hex2bin(id); id += 2;
			int len = hex2bin(id); id += 2;
			char buf[255];
			char *p = buf;

			syslog(LOG_ERR, "SubOpt: %d, Len: %d, '%.*s'", opt, len, len * 2, id);

			for (int i = 0; i < len; i++, p++)
				*p = hex2bin(id + i * 2);
			*p = '\0';

			switch (opt) {
			case 1:  /* Circuit Id */
				diam_avpgrp_add_raw(NULL, &grp, AVP_DHCP_CIRCUIT_ID, 0, VP_TRAVELPING, id, len * 2);
				break;

			case 2:  /* Remote Id */
				diam_avpgrp_add_raw(NULL, &grp, AVP_DHCP_REMOTE_ID, 0, VP_TRAVELPING, id, len * 2);
				break;

			case 6:  /* Subscriber Id */
				diam_avpgrp_add_raw(NULL, &grp, AVP_DHCP_SUBSCRIBER_ID, 0, VP_TRAVELPING, buf, len);
				break;

			default:
				break;
			}

			id += len * 2;
		}
	}

	if (optlist)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_OPTLIST, 0, VP_TRAVELPING, optlist);
	if (optreqlist)
		diam_avpgrp_add_string(NULL, &grp, AVP_DHCP_OPTREQLIST, 0, VP_TRAVELPING, optreqlist);

	if (!(base = event_init())) {
		syslog(LOG_ERR, "event_init failed", rc);
		return EXCODE_FAILURE;
	}

	dm_context_init(&ctx, base);

	if ((rc = dm_init_socket(&ctx, stype))) {
		event_base_free(base);
		syslog(LOG_ERR, "dm_init_socket failed (code = %d)", rc);
		return EXCODE_FAILURE;
	}
	if ((rc = dm_send_start_session(&ctx, CMD_FLAG_READWRITE, &timeout, NULL))) {
		dm_shutdown_socket(&ctx);
		event_base_free(base);
		syslog(LOG_ERR, "dm_send_start_session failed (code = %d)", rc);
		return EXCODE_FAILURE;
	}

	syslog(LOG_INFO, "sending: dm_send_cmd_dhcpinfo %s", argv[1]);

        rc = dm_generic_send_request(&ctx, ev, grp, NULL);
        dm_grp_free(grp);

	if (rc)
		syslog(LOG_ERR, "dm_send_cmd_dhcpinfo failed (code = %d)", rc);

	if ((rc = dm_send_end_session(&ctx))) {
		dm_shutdown_socket(&ctx);
		event_base_free(base);
		syslog(LOG_ERR, "dm_send_end_session failed (code = %d)", rc);
		return EXCODE_FAILURE;
	}
	dm_shutdown_socket(&ctx);
	event_base_free(base);

	return EXCODE_SUCCESS;
}
#endif

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
	else if (strcmp(progname, "hotplug") == 0)	/* it isn't possible to change the socket */
		ret = hotplug(argc, argv);		/* type right now */
#if defined(WITH_DHCP_DHCPD)
	else if (strcmp(progname, "dhcpinfo") == 0)
		ret = dhcpinfo(argc, argv);
#endif
#if defined(WITH_DHCP_ISC)
	else if (strcmp(progname, "dhcpnotify") == 0)
		ret = dhcpnotify(argc, argv);
#endif
#if defined(WITH_DHCP_DNSMASQ)
	else if (strcmp(progname, "dnsmasqnotify") == 0)
		ret = dnsmasqnotify(argc, argv);
#endif

	closelog();

	return ret;
}
