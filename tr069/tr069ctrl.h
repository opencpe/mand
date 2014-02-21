#ifndef _GWCTL_H_
#define _GWCTL_H_

#define CRLF "\r\n"

typedef enum _ctrl_command {
	TR069CTRL_UNDEF,
	TR069CTRL_BOOTSTRAP,
	TR069CTRL_COMMIT,
	TR069CTRL_GET,
	TR069CTRL_SET,
	TR069CTRL_ADD,
	TR069CTRL_DEL,
	TR069CTRL_IFUP,
	TR069CTRL_IFDOWN,
	TR069CTRL_WANUP,
	TR069CTRL_WANDOWN,
	TR069CTRL_WANRESTART,
	TR069CTRL_DUMP,
	TR069CTRL_SYSUP,
	TR069CTRL_GETDEVICE,
	TR069CTRL_CONFSAVE,
	TR069CTRL_CONFRESTORE,

	TR069CTRL_NEWCLIENT,
	TR069CTRL_DELCLIENT,
	TR069CTRL_CLIENTACC,
	TR069CTRL_REQACC,
	TR069CTRL_SETACC
} CTRL_COMMAND;

		/* return codes (considering the ones already "defined"
		   in /usr/include/sysexits.h) */
#define EXCODE_SUCCESS		0
#define EXCODE_USAGE		1
#define EXCODE_FAILURE		70

void parse_commandline(int, char **);

int tr069ctrl(int argc, char **argv);
int hotplug(int argc, char **argv);
int dhcpinfo(int argc, char **argv);

#endif
