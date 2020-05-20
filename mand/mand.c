/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
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

#include "expat.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_serialize.h"
#include "dm_deserialize.h"

#include "dm_dmconfig.h"
#include "dm_luaif.h"

#include "process.h"

#define DM_BASE_CONFIG "/etc/dm"
#define IPKG_BASE_CONFIG  "/jffs/etc/dm"

#define DM_DEFAULT_CONFIG "/etc/defaults/dm"
#define IPKG_DEFAULT_CONFIG  "/jffs/etc/defaults/dm"

#define DM_CONFIG   "/jffs/etc/dm.xml"

#define SDEBUG
#include "debug.h"

extern int libdmconfigSocketType;

/* support multiple event loops? */
#if EV_MULTIPLICITY
#define EV_P_UNUSED_ EV_P __attribute__((unused)),
#else
#define EV_P_UNUSED_
#endif

void dm_save(void)
{
	static pthread_mutex_t save_mutex = PTHREAD_MUTEX_INITIALIZER;

	char *fname;
	int fd;
	FILE *fout;

	pthread_mutex_lock(&save_mutex);

	fname = strdup(DM_CONFIG ".XXXXXX");
	if (fname && (fd = mkstemp(fname)) != -1) {
		fout = fdopen(fd, "w");
		if (fout) {
			dm_serialize_store(fout, S_CFG);
			fflush(fout);
			fsync(fd);
			fclose(fout);
			rename(fname, DM_CONFIG);
		} else {
			close(fd);
		}
	}
	free(fname);

	pthread_mutex_unlock(&save_mutex);
}

void dm_dump(int fd, const char *element)
{
	int fdout;
	FILE *fout;

	fdout = dup(fd);
	if (fdout <= 0)
		return;

	fout = fdopen(fdout, "a");
	if (fout) {
		if (element && *element)
			dm_serialize_element(fout, element, S_ALL);
		else
			dm_serialize_store(fout, S_ALL);
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

static void sigusr2_cb(EV_P_UNUSED_
		       ev_signal *w __attribute__ ((unused)),
		       int revents __attribute__ ((unused)))
{
	logx_level = logx_level == LOG_DEBUG ? LOG_NOTICE : LOG_DEBUG;
}

void usage(void)
{
}

static void dm_load_base_config(void)
{
	dm_deserialize_directory(DM_BASE_CONFIG, DS_BASECONFIG);
	dm_deserialize_directory(IPKG_BASE_CONFIG, DS_BASECONFIG);
}

static void dm_load_default_config(void)
{
	dm_deserialize_directory(DM_DEFAULT_CONFIG, DS_USERCONFIG);
	dm_deserialize_directory(IPKG_DEFAULT_CONFIG, DS_USERCONFIG);
}

int main(int argc, char *argv[])
{
	const struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	ev_signal signal_watcher;
	ev_signal sigusr2_watcher;

	int run_daemon = 0;
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

	while (-1 != (c = getopt(argc, argv, "dh"))) {
		switch(c) {
			case 'd':
				run_daemon = 1;
				break;

			case 'h':
				usage();
				exit(1);
				break;

			default:
				usage();
				exit(1);
				break;
		}
	}

	EV_DEFAULT;

	/* events are added to the most recently created event base by default */
	/* so create a cwmp event base AFTER the libdmconfig event base if necessary */

	signal(SIGPIPE, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	// signal(SIGINT, SIG_IGN);

	ev_signal_init(&signal_watcher, sigterm_cb, SIGTERM);
	ev_signal_start(EV_DEFAULT_UC_ &signal_watcher);

	ev_signal_init(&sigusr2_watcher, sigusr2_cb, SIGUSR2);
	ev_signal_start(EV_DEFAULT_UC_ &sigusr2_watcher);

	if (init_Lua_environment())
		debug("(): Couldn't initialize Lua environment");

	if (fp_Lua_function("fncStartup", 0))
		debug("(): Error during Lua function execution");

	dm_load_base_config();

	printf("deserialize "DM_CONFIG"\n");
	fin = fopen(DM_CONFIG, "r");
	if (fin) {
		dm_deserialize_store(fin, DS_USERCONFIG | DS_VERSIONCHECK);
		fclose(fin);
	} else {
		dm_load_default_config();
        }

	dm_notify_init(EV_DEFAULT_UC);

	libdmconfigSocketType = AF_INET;
	if (init_libdmconfig_server(EV_DEFAULT_UC))
		debug("Cannot initiate libdmconfig server\n");

	if (run_daemon)
		if (daemon(1, 0) != 0) {
			fprintf(stderr, "daemon failed: %s\n", strerror(errno));
			exit(1);
		}

	ev_loop(EV_DEFAULT_UC_ 0);

	dm_shutdown();

	printf("mem usage: %d\n", dm_mem);
	return 0;
}
