/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __DM_CFGSESSIONS_H
#define __DM_CFGSESSIONS_H

#include "dm_cache.h"
#include "dm_notify.h"
#include "dm_action.h"
#include "dm_dmconfig.h"

typedef enum _cfgStatus {
	CFGSESSION_INACTIVE,
	CFGSESSION_ACTIVE_LIBDMCONFIG,
	CFGSESSION_ACTIVE_CWMP,
	CFGSESSION_ACTIVE_LUAIF
} CFGSTATUS;

extern CFGSTATUS cfgSessionStatus;

static inline CFGSTATUS getCfgSessionStatus(void);
static inline void setCfgSessionStatus(CFGSTATUS s);

static inline CFGSTATUS
getCfgSessionStatus(void) {
	return cfgSessionStatus;
}

static inline void
setCfgSessionStatus(CFGSTATUS s) {
	if (getCfgSessionStatus() != CFGSESSION_INACTIVE &&
	    s == CFGSESSION_INACTIVE) {
		cache_reset();
		exec_actions_pre();
		exec_actions();
		exec_pending_notifications();
		processRequestedSessions();
	}

	cfgSessionStatus = s;
}

#endif

