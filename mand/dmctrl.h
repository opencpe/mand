#ifndef _GWCTL_H_
#define _GWCTL_H_

#define CRLF "\r\n"

typedef enum _ctrl_command {
	DMCTRL_UNDEF,
	DMCTRL_BOOTSTRAP,
	DMCTRL_COMMIT,
	DMCTRL_GET,
	DMCTRL_SET,
	DMCTRL_ADD,
	DMCTRL_DEL,
	DMCTRL_IFUP,
	DMCTRL_IFDOWN,
	DMCTRL_WANUP,
	DMCTRL_WANDOWN,
	DMCTRL_WANRESTART,
	DMCTRL_DUMP,
	DMCTRL_SYSUP,
	DMCTRL_GETDEVICE,
	DMCTRL_CONFSAVE,
	DMCTRL_CONFRESTORE,

	DMCTRL_NEWCLIENT,
	DMCTRL_DELCLIENT,
	DMCTRL_CLIENTACC,
	DMCTRL_REQACC,
	DMCTRL_SETACC
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
