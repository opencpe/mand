/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 travelping GmbH
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/types.h>
#include <dirent.h>

#include "dm_token.h"
#include "dm_store.h"

#include "tools/ipkg_tools.h"

#define SDEBUG
#include "debug.h"

void build_ipkg_list(void)
{
	char list[1024];
	int p = 0;

	DIR *dirp;
	struct dirent *dp;

	ENTER();

	if (!(dirp = opendir(IPKG_PLIST_DIR))) {
		EXIT();
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		char *e;
		int len;

		if (dp->d_name[0] == '.')
			continue;

		e = strrchr(dp->d_name, '.');
		if (!e)
			continue;

		if (strcmp(".list", e) != 0)
			continue;

		len = e - dp->d_name;
		if (p + len + 1 > sizeof(list))
		    continue;

		if (p != 0)
			list[p++] = ',';
		memcpy(list + p, dp->d_name, len);
		p += len;
	}
	list[p] = '\0';

	closedir(dirp);

	if (list[0]) {
		dm_set_string_by_selector((dm_selector){cwmp__InternetGatewayDevice,
					cwmp__IGD_DeviceInfo,
					cwmp__IGD_DevInf_X_TPLINO_NET_InstalledPackages, 0}, list, DV_NONE);
	}

	EXIT();
}
