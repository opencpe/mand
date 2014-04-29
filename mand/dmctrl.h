/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _GWCTL_H_
#define _GWCTL_H_

#define CRLF "\r\n"

typedef enum _ctrl_command {
	DMCTRL_UNDEF,
	DMCTRL_BOOTSTRAP,
	DMCTRL_COMMIT,
	DMCTRL_LIST,
	DMCTRL_GET,
	DMCTRL_SET,
	DMCTRL_ADD,
	DMCTRL_DEL,
	DMCTRL_FIND,
	DMCTRL_DUMP,
	DMCTRL_CONFSAVE,
	DMCTRL_CONFRESTORE,
	DMCTRL_RESTART,
	DMCTRL_SHUTDOWN,
} CTRL_COMMAND;

		/* return codes (considering the ones already "defined"
		   in /usr/include/sysexits.h) */
#define EXCODE_SUCCESS		0
#define EXCODE_USAGE		1
#define EXCODE_FAILURE		70

void parse_commandline(int, char **);

int dmctrl(int argc, char **argv);
int hotplug(int argc, char **argv);
int dhcpinfo(int argc, char **argv);

#endif
