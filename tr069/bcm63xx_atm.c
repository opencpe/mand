/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include <atmapidrv.h>

#include "tr069_token.h"
#include "tr069_store.h"

#define SDEBUG
#include "debug.h"
#include "ifup.h"

static int atm_fd = -1;

static int get_atm(void)
{
	if (atm_fd != -1) {
		/* test if the fd is still alive */
		struct pollfd pfd = {
			.fd = atm_fd,
			.events = POLLIN | POLLOUT
		};
		int r;

		r = poll(&pfd,  1, 0);
		debug("(): poll result: %d, errno: %d, revents: %x", r, errno, pfd.revents);
		if ((r == -1 && errno == EBADF) ||
		    pfd.revents & (POLLERR | POLLHUP | POLLNVAL) != 0) {
			close(atm_fd);
			atm_fd = -1;
		}
	}

	if (atm_fd == -1)
		if ((atm_fd = open("/dev/bcmatm0", O_RDWR)) == -1)
			perror("open bcmatm0");

	return atm_fd;
}

int bcm63xx_atm_ifcfg(struct AtmInterfaceCfg *icfg)
{
	int fd;

	if ((fd = get_atm()) != -1) {
		icfg->ulStructureId = ID_ATM_INTERFACE_CFG;

		ATMDRV_INTERFACE_CFG cfg = {
			.pInterfaceCfg = icfg,
			.baStatus = STS_ERROR,
		};

		if (ioctl(fd, ATMIOCTL_GET_INTERFACE_CFG, &cfg) == 0) {
			debug("(): ATMIOCTL_GET_INTERFACE_CFG: %d", cfg.baStatus);
			return cfg.baStatus;
		}
		debug("(): ATMIOCTL_GET_INTERFACE_CFG: %d, %d", cfg.baStatus, errno);
	}
	return STS_ERROR;
}


int bcm63xx_atm_drvstatus(void)
{
	ATM_INTERFACE_CFG icfg;

	return bcm63xx_atm_ifcfg(&icfg);
}

static int oper_status_map[] = {
	[OPRSTS_UP]      = 0,    /* Up */
	[OPRSTS_DOWN]    = 1,    /* Down */
	[OPRSTS_UNKNOWN] = 3,    /* Unavailable*/
};

DM_VALUE get_IGD_WANDev_i_ConDev_j_DSLLnkCfg_LinkStatus(tr069_id id,
							const struct tr069_element *elem,
							DM_VALUE val)
{
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.LinkStatus */
	ATM_INTERFACE_CFG icfg;

	if (bcm63xx_atm_ifcfg(&icfg) != STS_SUCCESS) {
		val.v.uint_val = 3; /* Unavailable */
	} else
		val.v.uint_val = oper_status_map[icfg.ulIfOperStatus];

	return val;
}

DM_VALUE get_IGD_WANDev_i_ConDev_j_DSLLnkCfg_ModulationType(tr069_id id,
							    const struct tr069_element *elem,
							    DM_VALUE val)
{
	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.ModulationType */
	return get_IGD_WANDev_i_DSLCfg_ModulationType(cwmp__IGD_WANDev_i_DSLCfg_ModulationType, elem, val);
}
