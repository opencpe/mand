#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <ev.h>
#include <event.h>

#include "routers.h"

#include "expat.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_serialize.h"
#include "tr069_deserialize.h"
#include "tr069_autogen.h"

#include "tr069_dmconfig.h"
#include "tr069_luaif.h"

#include "ifup.h"
#include "uevent.h"
#include "process.h"
#include "session.h"
#include "radius.h"
#include "tr069_event_queue.h"
#include "tr069_request_queue.h"
#include "ftools.h"

#define TR069_BASE_CONFIG "/etc/dm"
#define IPKG_BASE_CONFIG  "/jffs/etc/dm"

#define TR069_DEFAULT_CONFIG "/etc/defaults/dm"
#define IPKG_DEFAULT_CONFIG  "/jffs/etc/defaults/dm"

#define TR069_CONFIG   "/jffs/etc/tr069.xml"
#define TR069_EVENTS   "/jffs/etc/dm_events.xml"
#define TR069_REQUESTS "/jffs/etc/dm_requests.xml"

#define SDEBUG
#include "debug.h"

extern int libdmconfigSocketType;

time_t igd_parameters_tstamp;
int mngt_srv_url_change;

struct _fw_callbacks fw_callbacks;
int firmware_upgrade = 0;
int default_deserialized = 0;
pthread_mutex_t firmware_upgrade_mutex = PTHREAD_MUTEX_INITIALIZER;

void build_ipkg_list(void);	/* in tr069_ipkg.c */
void config_epmd(void);		/* in if_ofswitch.c */

void tr069_save(void)
{
	static pthread_mutex_t save_mutex = PTHREAD_MUTEX_INITIALIZER;

	char *fname;
	int fd;
	FILE *fout;

	pthread_mutex_lock(&save_mutex);

	fname = strdup(TR069_CONFIG ".XXXXXX");
	if (fname && (fd = mkstemp(fname)) != -1) {
		fout = fdopen(fd, "w");
		if (fout) {
			tr069_serialize_store(fout, S_CFG);
			fclose(fout);
			rename(fname, TR069_CONFIG);
		} else {
			close(fd);
		}
	}
	free(fname);

	pthread_mutex_unlock(&save_mutex);
}

void tr069_save_events(void)
{
	char *fname;
	int fd;
	FILE *fout;

	fname = strdup(TR069_EVENTS".XXXXXX");
	if ((fd = mkstemp(fname)) < 0) {
		free(fname);
		return;
	}
	fout = fdopen(fd, "w");
	if (fout) {
		tr069_serialize_events(fout);
		fclose(fout);
		rename(fname, TR069_EVENTS);
		free(fname);
	}
}

void tr069_load_events(void)
{
	FILE *fin;

	fin = fopen(TR069_EVENTS, "r");
	if (fin) {
		unlink(TR069_EVENTS);
		tr069_deserialize_events(fin);
		fclose(fin);
	}
}

void tr069_save_requests(void)
{
	char *fname;
	int fd;
	FILE *fout;

	fname = strdup(TR069_REQUESTS ".XXXXXX");
	if ((fd = mkstemp(fname)) < 0) {
		free(fname);
		return;
	}
	fout = fdopen(fd, "w");
	if (fout) {
		tr069_serialize_requests(fout);
		fclose(fout);
		rename(fname, TR069_REQUESTS);
		free(fname);
	}
}

void tr069_load_requests(void)
{
	FILE *fin;

	fin = fopen(TR069_REQUESTS, "r");
	if (fin) {
		unlink(TR069_REQUESTS);
		tr069_deserialize_requests(fin);
		fclose(fin);
	}
}

void tr069_dump(int fd, const char *element)
{
	int fdout;
	FILE *fout;

	fdout = dup(fd);
	if (fdout <= 0)
		return;

	fout = fdopen(fdout, "a");
	if (fout) {
		if (element && *element)
			tr069_serialize_element(fout, element, S_ALL);
		else
			tr069_serialize_store(fout, S_ALL);
		fclose(fout);
	}
}

static void sigterm_cb(EV_P_
		       ev_signal *w __attribute__ ((unused)),
		       int revents __attribute__ ((unused)))
{
	//	lan_all_ifdown();

	ev_unloop(EV_A_ EVUNLOOP_ALL);
}

static void sigusr2_cb(EV_P_
		       ev_signal *w __attribute__ ((unused)),
		       int revents __attribute__ ((unused)))
{
	logx_level = logx_level == LOG_DEBUG ? LOG_NOTICE : LOG_DEBUG;
}

void usage(void)
{
}

static void dm_load_base_config()
{
	tr069_deserialize_directory(TR069_BASE_CONFIG, DS_BASECONFIG);
	tr069_deserialize_directory(IPKG_BASE_CONFIG, DS_BASECONFIG);
}

static void dm_load_default_config()
{
	tr069_deserialize_directory(TR069_DEFAULT_CONFIG, DS_USERCONFIG);
	tr069_deserialize_directory(IPKG_DEFAULT_CONFIG, DS_USERCONFIG);
}

void tr069_reboot_actions()
{
	stop_scg_zones_radius();
	tr069_save_events();
	tr069_save_requests();
}

static DM_RESULT
readIntoBinaryValue(const char *filename, tr069_selector sel)
{
	FILE *file;
	uint8_t *data;
	struct stat filestat;

	int r;

	ENTER();

	if (stat(filename, &filestat) ||
	     !(file = fopen(filename, "r"))) {
		EXIT();
		return DM_ERROR;
	}

	r = !(data = malloc(filestat.st_size)) ||
	    !fread(data, filestat.st_size, 1, file) ||
	    tr069_set_binary_data_by_selector(sel, filestat.st_size, data, DV_UPDATED);
	    		/* FIXME: dupplicate allocation of value's data is avoidable */

	free(data);
	fclose(file);

	EXIT();
	return r ? DM_ERROR : DM_OK;
}

int main(int argc, char *argv[])
{
	const struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	ev_signal signal_watcher;
	ev_signal sigusr2_watcher;

	int run_daemon = 1;
	int c;
	FILE *fin;

	/* switch working dir to /tmp so that logfiles can be written */
	chdir("/tmp");

	/*
	 * prevent any spawned processes from inheriting LD_PRELOAD
	 * (e.g. memory debugging libraries)
	 */
	unsetenv("LD_PRELOAD");

	/* unlimited size for cores */
	setrlimit(RLIMIT_CORE, &rlim);

	logx_open(basename(argv[0]), LOG_CONS | LOG_PID | LOG_PERROR, LOG_DAEMON);
	logx_level = LOG_DEBUG;

	while (-1 != (c = getopt(argc, argv, "hf"))) {
		switch(c) {
			case 'h':
				usage();
				exit(1);
				break;

			case 'f':
				run_daemon = 0;
				break;

			default:
				usage();
				exit(1);
				break;
		}
	}

	EV_DEFAULT;

	event_init();
	/* events are added to the most recently created event base by default */
	/* so create a cwmp event base AFTER the libdmconfig event base if necessary */

	signal(SIGPIPE, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

	ev_signal_init(&signal_watcher, sigterm_cb, SIGTERM);
	ev_signal_start(EV_DEFAULT_UC_ &signal_watcher);

	ev_signal_init(&sigusr2_watcher, sigusr2_cb, SIGUSR2);
	ev_signal_start(EV_DEFAULT_UC_ &sigusr2_watcher);

	init_uevent(EV_DEFAULT_UC);

	if (init_Lua_environment())
		debug("(): Couldn't initialize Lua environment");

	if (fp_Lua_function("fncStartup", 0))
		debug("(): Error during Lua function execution");

	dm_load_base_config();

	printf("deserialize "TR069_CONFIG"\n");
	fin = fopen(TR069_CONFIG, "r");
	if (fin) {
		tr069_deserialize_store(fin, DS_USERCONFIG | DS_VERSIONCHECK);
		fclose(fin);
	} else {
		default_deserialized = init_auto_default_store();
		dm_load_default_config();
        }

	build_ipkg_list();

#if defined(WITH_BRCM43XX)
	int router = getRouterBrand();
	/** VAR: InternetGatewayDevice.DeviceInfo.HardwareVersion */
	tr069_set_string_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
						      cwmp__IGD_DeviceInfo,
                                                      cwmp__IGD_DevInf_HardwareVersion, 0}, routes_models[router], DV_NONE);
#endif

#if 0
	printf("serialize\n");
	tr069_serialize_store(stdout,  S_ALL);
#endif

	tr069_load_events();
	tr069_load_requests();

	if (run_daemon)
		if (daemon(1, 0) != 0) {
			fprintf(stderr, "daemon failed: %s\n", strerror(errno));
			exit(1);

		}

	tr069_notify_init(EV_DEFAULT_UC);
	supervisor_init(EV_DEFAULT_UC);
	net_sched_init();
	scg_zones_init();

	libdmconfigSocketType = AF_INET;
	if (init_libdmconfig_server(EV_DEFAULT_UC))
		debug("Cannot initiate libdmconfig server\n");

	if_startup();
	start_scg_zones();

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_LoggingEnabled */
	if (!tr069_get_bool_by_selector((tr069_selector) {cwmp__InternetGatewayDevice,
							  cwmp__IGD_DeviceInfo,
							  cwmp__IGD_DevInf_X_TPLINO_LoggingEnabled, 0})) {
		logx_level = LOG_NOTICE;
	}

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.SSL_Certificate */
	readIntoBinaryValue(LUCITTPD_SSL_CRT, (tr069_selector) { cwmp__InternetGatewayDevice,
								 cwmp__IGD_X_TPLINO_NET_HTTPServers,
			    					 cwmp__IGD_HTTPSrvs_SSL_Certificate, 0});
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.SSL_Key */
	readIntoBinaryValue(LUCITTPD_SSL_KEY, (tr069_selector) { cwmp__InternetGatewayDevice,
								 cwmp__IGD_X_TPLINO_NET_HTTPServers,
			    					 cwmp__IGD_HTTPSrvs_SSL_Key, 0});
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_HTTPServers.SSL_CA_Certificate */
	readIntoBinaryValue(LUCITTPD_SSL_CA, (tr069_selector) { cwmp__InternetGatewayDevice,
								cwmp__IGD_X_TPLINO_NET_HTTPServers,
			    					cwmp__IGD_HTTPSrvs_SSL_CA_Certificate, 0});

	/*
	 * Configure Erlang Port Mapper Daemon via process environment
	 */
	config_epmd();

	if (fp_Lua_function("fncAdminPasswd", 0))
		debug("(): Error during Lua function execution");

	ev_loop(EV_DEFAULT_UC_ 0);

	tr069_shutdown();

	printf("mem usage: %d\n", tr069_mem);
	return 0;
}
