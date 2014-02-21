/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <syslog.h>

#include "tr069_token.h"
#include "tr069_store.h"

#define SDEBUG
#include "debug.h"

#include "sol.h"
#include "process.h"
#include "utils/logx.h"

#define SOL_TRIGGERD "/usr/bin/sol-triggerd"

static int sol_id = -1;

static char **
update_sol_argv(void)
{
	struct in_addr addr;
	static char ipaddr[INET_ADDRSTRLEN];

	static char *argv[] = {
		SOL_TRIGGERD,
		"-l", ipaddr,
		NULL, /* optional "-x" */
		NULL
	};

	/** VAR: InternetGatewayDevice.DeviceInfo.SyslogServer */
	addr = tr069_get_ipv4_by_selector((tr069_selector){
		cwmp__InternetGatewayDevice,
		cwmp__IGD_DeviceInfo,
		cwmp__IGD_DevInf_SyslogServer, 0
	});
	inet_ntop(AF_INET, &addr, ipaddr, INET_ADDRSTRLEN);

	/** VAR: InternetGatewayDevice.DeviceInfo.X_TPLINO_LoggingEnabled */
	argv[3] = tr069_get_bool_by_selector((tr069_selector) {
		cwmp__InternetGatewayDevice,
        	cwmp__IGD_DeviceInfo,
		cwmp__IGD_DevInf_X_TPLINO_LoggingEnabled, 0
	}) ? "-x" : NULL;

	return argv;
}

static enum process_action
sol_reaped_cb(struct process_info_t *p, enum process_state state,
	      int status __attribute__((unused)),
	      void *ud __attribute__((unused)))
{
	switch (state) {
	case PROCESS_RUNNING:
		/* undesired crash, keep debug logging synchronized */
		change_process_argv(p, update_sol_argv());
		return PROCESS_RESTART;
	case PROCESS_DYING:
		/* desired termination */
		return PROCESS_REMOVE;
	default:
		break;
	}

	/* shouldn't be reached */
	return PROCESS_NOTHING;
}

void
start_sol_triggerd(void)
{
	sol_id = supervise_cb(update_sol_argv(),
			      PROCESS_DEFAULT_MAX_RESTARTS,
			      PROCESS_DEFAULT_RESTART_TIMESPAN,
			      sol_reaped_cb, NULL);
}

void
stop_sol_triggerd(void)
{
	if (sol_id > 0) {
		kill_supervise(sol_id, SIGTERM);
		sol_id = -1;
	}
}

/*
 * toggle log level
 */
void
toggle_sol_triggerd(void)
{
	if (sol_id > 0)
		signal_supervise(sol_id, SIGUSR2);
}

