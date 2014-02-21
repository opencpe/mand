#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

#define SDEBUG
#include "debug.h"

#define DEBUG

#define DEV_FILE "/dev/Switch"

#define DEFAULT_VM {1,1,1,1}
#define DMZ_ON_PORT_4_VM {1,1,1,0}
#define ONE_VLN_PER_PORT_VM {0,1,2,3}
#define HALF_SWITCH_VM {1,1,2,2}

static int vlan_map_type[4][4] =
{
	DEFAULT_VM,
	DMZ_ON_PORT_4_VM,
	HALF_SWITCH_VM,
	ONE_VLN_PER_PORT_VM
};

typedef enum {
	SWITCH_MARVELL_6060,
	SWITCH_MARVELL_6063,
	SWITCH_KENDIN_8995X,
	SWITCH_ADM_6995,
	SWITCH_RTL_8335
} SUPPORTED_SWITCHES_E;

/* Switch Identification */
typedef struct {
	uint32_t internalPortNum;    /* this is the "CPU"/internal port number needed
				      for start configuration */
	uint32_t miiBase;            /* Base access for MDIO */
	uint32_t channelNumber;      /* channel number for accesing the PHY*/
	uint32_t instanceId;         /* intstance Id, which is referred to when application asks to turn to the driver */
	SUPPORTED_SWITCHES_E switchType;
} SWITCH_INIT, *PSWITCH_INIT;

typedef struct _switch_ioctl_cmd_t{
	uint32_t t_opcode;
	uint32_t  instanceId;
	unsigned short TrailerMode;
	union {
		struct {
			PSWITCH_INIT pSwitchInfo;
			uint32_t NumOfSwitches;
			uint32_t data_size;
		} SWITCH_info;
		struct {
			uint32_t PortNum;
			uint32_t Status;
		} PORT_config;

	} msg;
} switch_ioctl_cmd_t;

#define SWITCH_DRV_IOCTL_MAGIC 'w'
#define SWITCH_IOCTL _IOWR(SWITCH_DRV_IOCTL_MAGIC, 0, switch_ioctl_cmd_t)

static int marvell_port_pbvm_val[6] =
{
	0x01,  /* 88E6060 PORT 0 = DG834(G) PORT 4 */
	0x02,  /* 88E6060 PORT 1 = DG834(G) PORT 3 */
	0x04,  /* 88E6060 PORT 2 = DG834(G) PORT 2 */
	0x08,  /* 88E6060 PORT 3 = DG834(G) PORT 1 */
	0x10,  /* 88E6060 PORT 4 = N.C. */
	0x20   /* 88E6060 PORT 5 = INTERNAL (CPU) */
};

typedef int marvell_vlan_map_t[6];
typedef int dg_vlan_map_t[4];


marvell_vlan_map_t * Dg2MarvellVM(dg_vlan_map_t dg_VM, marvell_vlan_map_t * marvell_VM)
{
	for (int i = 3; i >= 0; i--) {
		debug("(): mapping: %d -- %d", abs(i - 3), i);
		*marvell_VM[abs(i - 3)] = dg_VM[i];
	}
	*marvell_VM[4] = 0; /* Mvl port 4 => vlan 0 */
	*marvell_VM[5] = 1;

 /* Mvl port 5 => vlan 1, pas d'importance
ici, le port 5 fait partie de tous les VLANS. */

	return marvell_VM;
}

int DG_setPortVlan(dg_vlan_map_t user_VM)
{
	SWITCH_INIT swinit;
	switch_ioctl_cmd_t cmd;
	int fd;
	marvell_vlan_map_t *new_vlan_map = (marvell_vlan_map_t *)malloc(sizeof(marvell_vlan_map_t));

	/* Conversion VLAN Port DG vers VLAN port Marvell 88E6060 */
	new_vlan_map = Dg2MarvellVM(user_VM, new_vlan_map);

	/* Ouverture du fichier special /dev/Switch pour dialoguer avec
 	*  le switch Marvell */
	if (!(fd = open(DEV_FILE, O_RDWR)))
	{
		debug("(): error, failed to open device: %s\n", DEV_FILE);
		return -1;
	}
	/* Appel INFOGET, apparemment obligatoire avant de pouvoir
	 * controler le switch */

	cmd.t_opcode = 1; // INFOGET
	cmd.msg.SWITCH_info.pSwitchInfo = &swinit;
	cmd.msg.SWITCH_info.data_size = sizeof(swinit);
	cmd.msg.SWITCH_info.NumOfSwitches = 1;
	if (!(ioctl(fd, SWITCH_IOCTL, &cmd))) {
		debug("(): ioctl INFOGET: ok !\n");

		/* Ecriture des nouvelles valeurs de VLANs, par l'appel
		 *  PORT_SETPBVM.
		 *  Comme définit dans l'appel ioctl_SetPBVM:
		 *  PORT_config.PortNum contient le numero du port.
		 *  PORT_config.Status contient la valeur a ecrire dans le
		 *  registre.
		 */

		for (int portNum = 0; portNum < 6; portNum++) {
			int portVlan, portVmVal;

			portVlan =  *new_vlan_map[portNum];
			portVmVal = 0x20;
			for (int i = 0; i < 5; i++) {
				/* dans cette boucle on n'inclut pas la valeur du port
				 * 5, car elle est ajoutée d'office plus haut. tous les port peuvent
				 * communiquer avec le port CPU, ce port fait donc partie
				 * de tous les VLANS comme ecrit plus haut */

				if (*new_vlan_map[i] == portVlan)
					portVmVal += marvell_port_pbvm_val[i];
			}
			portVmVal -= marvell_port_pbvm_val[portNum];
			/* si on est sur le port 5, la valeur est toujours
			 *  0x1F. */
			if (portNum == 5)
				portVmVal = 0x1F;

			debug("(): setting port: %d: 0x%x\n", portNum, portVmVal);

			cmd.msg.PORT_config.PortNum = portNum;
			cmd.msg.PORT_config.Status = portVmVal;
			cmd.t_opcode = 30;  // PORT_SETPBVM opcode

			ioctl(fd, SWITCH_IOCTL, &cmd);
			debug("(): Setting Port %d Vlan %d\n", portNum, portVlan);
		}
	}else
		debug("Error: ioctl failed\n");

	close(fd);
	return 0;
}

void if_marvell(void) {
	DG_setPortVlan(vlan_map_type[3]);
}
