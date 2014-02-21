#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <inttypes.h>
#include <pthread.h>
#include <atm.h>

#if defined(WITH_BCM63XX)
#define CONFIG_MIPS_BRCM

#include "include/linux/atmdev.h"
#include <linux/atmbr2684.h>
#include "include/linux/atmrt2684.h"
#include <linux/atmclip.h>

#include <adsldrv.h>
#include <atmapidrv.h>

#else

#include <linux/atmdev.h>
#include <linux/atmbr2684.h>
#include <linux/atmclip.h>

#endif

#include "tr069_token.h"
#include "tr069_store.h"
#include "list.h"

#define SDEBUG
#include "debug.h"
#include "ifup.h"

#define ATM_BR_DEVICE "nas%d"
#define ATM_IP_DEVICE "atmip%d"

#define PPP_CONF "/var/etc/ppp.options"
#define ATMARPD "/usr/sbin/atmarpd"

static int atmarpd = -1;

struct atm_info_t {
	struct atm_info_t	*next;
	int			id;
	int			ifnum;
	int			proto;
	struct sockaddr_atmpvc	addr;
	int			da_type;
	int			vpi, vci;
	int			encap;
	int			ifmode;
	int			fd;
};

static struct {
	struct atm_info_t	*next;
	pthread_mutex_t		mutex;
	uint32_t		idmap;
} atm_info_head = { .next = NULL, .mutex = PTHREAD_MUTEX_INITIALIZER, .idmap = 0 };

static int atm_pppoa_ifup(const char *, const tr069_selector, struct tr069_instance_node *);

static inline int atm_int_cmp(struct atm_info_t *node, int id)
{
	return INTCMP(node->id, id);
}

static inline int atm_node_cmp(struct atm_info_t *n1, struct atm_info_t *n2)
{
	return INTCMP(n1->id, n2->id);
}

void get_atm_iface(int card, int ifc, char *iface, int size)
{
	struct atm_info_t *p;
	int id = ((card & 0xff) << 8) | (ifc & 0xff);

	pthread_mutex_lock(&atm_info_head.mutex);

	list_search(struct atm_info_t, atm_info_head, id, atm_int_cmp, p);
	if (p)
		snprintf(iface, size, ATM_BR_DEVICE, p->ifnum);

	pthread_mutex_unlock(&atm_info_head.mutex);
}

/* Create atmxxx interface */
static int create_rt(const char *ifname, const struct atm_info_t *ai)
{
	int err;
	int sock;

	if ((sock = socket(PF_ATMPVC, SOCK_DGRAM, ATM_AAL5)) < 0) {
		perror("socket");
		return -1;
	}


	/* create the device with ioctl: */
	struct atm_newif_rt2684 ni;

	ni.backend_num = ATM_BACKEND_RT2684;
	strcpy(ni.ifname, ifname);

	err = ioctl(sock, ATM_NEWBACKENDIF, &ni);
	close(sock);

	if (err == 0)
		debug(": Interface \"%s\" created sucessfully\n",
		      ni.ifname);
	else
		debug(": Interface \"%s\" could not be created, reason: %s\n",
		      ni.ifname, strerror(errno));

	return err;
}

static int create_br(const char *ifname, const struct atm_info_t *ai)
{
	int err;
	int sock;

	if ((sock = socket(PF_ATMPVC, SOCK_DGRAM, ATM_AAL5)) < 0) {
		perror("socket");
		return -1;
	}
	/* create the device with ioctl: */
	struct atm_newif_br2684 ni;

	ni.backend_num = ATM_BACKEND_BR2684;
	ni.media = BR2684_MEDIA_ETHERNET;
	ni.mtu = 1500;
#if defined(WITH_AR7)
	ni.payload = ai->ifmode;
#endif

	strcpy(ni.ifname, ifname);
	err = ioctl(sock, ATM_NEWBACKENDIF, &ni);
	close(sock);

	if (err == 0)
#if defined(WITH_AR7)
		debug(": Interface \"%s\" (mtu=%d, payload=%s) created sucessfully\n",
		      ni.ifname, ni.mtu, ni.payload ? "bridged" : "routed");
#else
		debug(": Interface \"%s\" (mtu=%d) created sucessfully\n",
		      ni.ifname, ni.mtu);
#endif
	else
		debug(": Interface \"%s\" could not be created, reason: %s\n",
		      ni.ifname, strerror(errno));

	return err;
}

static int connect_vcc(const char *ifname, struct atm_info_t *ai, int bufsize, int mtu)
{
	int err;
	struct atm_qos qos;
	int fd;

	debug(": Communicating over ATM %d.%d.%d, encapsulation: %s\n",
	       ai->addr.sap_addr.itf, ai->addr.sap_addr.vpi, ai->addr.sap_addr.vci,
	       ai->encap ? "LLC" : "VC mux");

	if ((fd = socket(PF_ATMPVC, SOCK_DGRAM, ATM_AAL5)) < 0)
		debug(": failed to create socket %d, reason: %s",
		       errno, strerror(errno));

	fcntl(fd, F_SETFD, FD_CLOEXEC | fcntl(fd, F_GETFD));

	memset(&qos, 0, sizeof(qos));
	qos.aal = ATM_AAL5;
	qos.txtp.traffic_class = ATM_UBR;
	qos.txtp.max_sdu = mtu;
	qos.txtp.pcr = ATM_MAX_PCR;
	qos.rxtp = qos.txtp;

	if ((err = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize))))
		debug(": setsockopt SO_SNDBUF: (%d) %s\n", err,
		      strerror(err));

	if (setsockopt(fd, SOL_ATM, SO_ATMQOS, &qos, sizeof(qos)) < 0)
		debug(": setsockopt SO_ATMQOS %d", errno);

	err = connect(fd, (struct sockaddr *)&ai->addr, sizeof(struct sockaddr_atmpvc));

	if (err < 0) {
		perror("failed to connect on socket");
		close(fd);
		return -1;
	}


	ai->fd = fd;
	return 0;
}

static int attach_rt2vcc(const char *ifname, struct atm_info_t *ai)
{
	int err;
	struct atm_backend_rt2684 be;

	/* attach the vcc to device: */

	memset(&be, 0, sizeof(be));
	be.backend_num = ATM_BACKEND_RT2684;
	be.ifspec.method = RT2684_FIND_BYIFNAME;
	strcpy(be.ifspec.spec.ifname, ifname);
	be.encaps = ai->encap;

	err = ioctl(ai->fd, ATM_SETBACKEND, &be);
	if (err == 0)
		debug(": Interface %s configured", ifname);
	else {
		debug(": Could not configure interface %s: %s", ifname,
		      strerror(errno));
		close(ai->fd);
		ai->fd = -1;
		return -1;
	}

	return 0;
}

static int attach_br2vcc(const char *ifname, struct atm_info_t *ai)
{
	int err;
	struct atm_backend_br2684 be;

	/* attach the vcc to device: */

	memset(&be, 0, sizeof(be));
	be.backend_num = ATM_BACKEND_BR2684;
	be.ifspec.method = BR2684_FIND_BYIFNAME;
	strcpy(be.ifspec.spec.ifname, ifname);
	be.fcs_in = BR2684_FCSIN_NO;
	be.fcs_out = BR2684_FCSOUT_NO;
	be.fcs_auto = 0;
	be.encaps = ai->encap;
#if defined(WITH_AR7)
	be.payload = ai->ifmode;
#endif
	be.has_vpiid = 0;
	be.send_padding = 0;
	be.min_size = 0;

	err = ioctl(ai->fd, ATM_SETBACKEND, &be);
	if (err == 0)
		debug(": Interface configured");
	else {
		debug(": Could not configure interface: %s",
		      strerror(errno));
		close(ai->fd);
		ai->fd = -1;
		return -1;
	}

	return 0;
}


static inline struct atm_info_t *atm_info_dup(const struct atm_info_t *p)
{
	struct atm_info_t *n;

	n = malloc(sizeof(struct atm_info_t));
	if (!n)
		return NULL;
	memcpy(n, p, sizeof(struct atm_info_t));
	n->next = NULL;
	return n;
}

static inline void atm_info_cpy(struct atm_info_t *n, const struct atm_info_t *p)
{
	struct atm_info_t *next;

	next = n->next;
	memcpy(n, p, sizeof(struct atm_info_t));
	n->next = next;
}

static struct atm_info_t *get_atm_device(const tr069_selector sel, const struct atm_info_t *ai)
{
	int id;
	struct atm_info_t *p;

	id = ((sel[2] & 0xff) << 8) | (sel[4] & 0xff);

	list_search(struct atm_info_t, atm_info_head, id, atm_int_cmp, p);
	if (p) {
		if (p->fd > 0) {
			debug("warning: reconfiguring active interface");
			close(p->fd);
			p->fd = -1;
		}
		atm_info_cpy(p, ai);
	} else {
		p = atm_info_dup(ai);
		debug(": atm_info_head.idmap: %d", atm_info_head.idmap);
		p->id = id;
		p->ifnum = ffs(~(atm_info_head.idmap)) - 1;
		debug(": ifnum: %d", p->ifnum);
		atm_info_head.idmap |= 1 << p->ifnum;
		debug(": atm_info_head.idmap: %d", atm_info_head.idmap);
		list_insert(struct atm_info_t, atm_info_head, p, atm_node_cmp);
	}

	return p;
}

static int atm_ipoa_up(const char *device __attribute__ ((unused)), const tr069_selector sel, const struct atm_info_t *ai)
{
	char ifname[IFNAMSIZ];
	struct atm_info_t *p;

	ENTER();

	insmod("rt2684");

	pthread_mutex_lock(&atm_info_head.mutex);

	p = get_atm_device(sel, ai);

	snprintf(ifname, sizeof(ifname), ATM_IP_DEVICE, p->ifnum);
	if_add2ifmap(ifname, sel);

	if (create_rt(ifname, p) == 0) {
		connect_vcc(ifname, p, 8192, RFC1483LLC_LEN + RFC1626_MTU);
		attach_rt2vcc(ifname, p);
	}

	pthread_mutex_unlock(&atm_info_head.mutex);

	EXIT();
	return 0;
}

static int atm_encapif_up(const char *device __attribute__ ((unused)), const tr069_selector sel, const struct atm_info_t *ai)
{
	char ifname[IFNAMSIZ];
	struct atm_info_t *p;

	ENTER();

	insmod("br2684");

	pthread_mutex_lock(&atm_info_head.mutex);

	p = get_atm_device(sel, ai);

	snprintf(ifname, sizeof(ifname), ATM_BR_DEVICE, p->ifnum);
	if_add2ifmap(ifname, sel);

	if (create_br(ifname, p) == 0) {
		connect_vcc(ifname, p, 8192, 1524);
		attach_br2vcc(ifname, p);
	}
	pthread_mutex_unlock(&atm_info_head.mutex);

	EXIT();
	return 0;
}

int adsl_ifup(const char *device __attribute__ ((unused)), const tr069_selector sel)
{
	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig */
	if (sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANDSLInterfaceConfig) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.Enable */
	tr069_selector if_en;

	tr069_selcpy(if_en, sel);
	if_en[4] = cwmp__IGD_WANDev_i_DSLCfg_Enable; if_en[5] = 0;

	if (!tr069_get_bool_by_selector(if_en)) {
		EXIT();
		return -1;
	}

#if defined(WITH_BCM63XX)
	{
		dev_t dev;

		dev = makedev(ADSLDRV_MAJOR, 0);
		mknod("/dev/bcmadsl0", S_IFCHR |S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP, dev);
	}

	vsystem("/usr/sbin/adslctl start --up");
	vsystem("/usr/sbin/adslctl configure --mod a");

	insmod("blaa_dd");
	//atm_start(device, sel);
#endif

	EXIT();
	return 0;
}

static int get_atm_da(struct atm_info_t *ai, const char *da)
{
	if (sscanf(da, "PVC: %d/%d", &ai->vpi, &ai->vci) == 2) {
		ai->addr.sap_family = AF_ATMPVC;
		ai->addr.sap_addr.itf = 0;
		ai->addr.sap_addr.vpi = ai->vpi;
		ai->addr.sap_addr.vci = ai->vci;
		ai->da_type = 1;
 	} else if (strncasecmp(da, "SVC: ", 5) == 0) {
		if (text2atm(da+5, (struct sockaddr *)&ai->addr, sizeof(ai->addr), T2A_SVC) < 0) {
			debug("unable to parse SVC addr: %s", da+5);
			return 0;
		}
		ai->da_type = 2;
	} else {
		debug("unknown DestinationAddress: %s", da);
		return 0;
	}
	return 1;
}

/*
 * start the atm interface and add all configured vc's
 */
int atm_ifup(const char *device, const tr069_selector sel)
{
	struct tr069_instance_node *ift_node;
	struct tr069_value_table *ift;
	struct tr069_value_table *dslc;

	int encap;
	int rc = 0;

	struct atm_info_t ai;

	ENTER();

        /** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
        if (sel[1] != cwmp__IGD_WANDevice ||
            sel[2] == 0 ||
            sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
            sel[4] == 0 ||
	    sel[5] != 0) {
                EXIT();
                return 0;
        }

#if defined(WITH_BCM63XX)
	{
		dev_t dev;

		dev = makedev(ATMDRV_MAJOR, 0);
		mknod("/dev/bcmatm0", S_IFCHR |S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP, dev);

		if (bcm63xx_atm_drvstatus() != STS_SUCCESS) {
			rc = vsystem("/usr/sbin/atmctl start");
			debug("atmctl start rc: %d", WEXITSTATUS(rc));

			if (WEXITSTATUS(rc) != 0) {
				EXIT();
				return 0;
			}
		}
	}
#endif

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	ift_node = tr069_get_instance_node_by_selector(sel);
	if (!ift_node) {
		EXIT();
		return 0;
	}
	ift = DM_TABLE(ift_node->table);

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig */
	dslc = tr069_get_table_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_WANDSLLinkConfig);
	if (!dslc) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.Enable */
	if (!tr069_get_bool_by_id(dslc, cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_Enable)) {
		EXIT();
		return 0;
	}

	memset(&ai, 0, sizeof(struct atm_info_t));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.LinkType */
	ai.proto = tr069_get_int_by_id(dslc, cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_LinkType);

	ai.da_type = -1;
	ai.ifmode = 1;           /* ATM bridged */

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.DestinationAddress */
	if (!get_atm_da(&ai, tr069_get_string_by_id(dslc,
						    cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_DestinationAddress))) {
		EXIT();
		return -1;
	}

#if defined(WITH_BCM63XX)
	vasystem("/usr/sbin/atmctl operate vcc --add %d.%d.%d aal5 1 unknown --addq %d.%d.%d 64 0",
		 ai.addr.sap_addr.itf, ai.addr.sap_addr.vpi, ai.addr.sap_addr.vci,
		 ai.addr.sap_addr.itf, ai.addr.sap_addr.vpi, ai.addr.sap_addr.vci);
#endif

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.ATMEncapsulation */
	ai.encap = -1;
	encap = tr069_get_enum_by_id(dslc, cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_ATMEncapsulation);
	if (encap == 0)
		ai.encap = BR2684_ENCAPS_LLC;
	else if (encap == 1)
		ai.encap = BR2684_ENCAPS_VC;
	else {
		debug("unknown ATMEncapsulation: %d", encap);
		EXIT();
		return -1;
	}

	switch (ai.proto) {
		case 1:								/* IPoA */
		case 4:								/* CIP */
			ai.ifmode = 0;       /* routed */
			rc = atm_ipoa_up(device, sel, &ai);
			break;
		case 0:								/* EoA */
		case 3:								/* PPPoE (obsolete) */
			rc = atm_encapif_up(device, sel, &ai);
			break;
		case 2:								/* PPPoA */
			rc = atm_pppoa_ifup(device, sel, ift_node);
			break;
		default:
			break;
	}

	EXIT();
	return rc;
}

static int pppoa_start_if(const char *device,
			  tr069_id wandev,
			  struct tr069_instance_node *ift_node,
			  struct tr069_instance_node *pppc_node)
{
	FILE *fout;
	struct atm_info_t ai;
	int encap;
	struct tr069_value_table *dslc;
	struct tr069_value_table *ift = DM_TABLE(ift_node->table);
	struct tr069_value_table *pppc = DM_TABLE(pppc_node->table);

	if (!(fout = fopen(PPP_CONF, "w"))) {
		fprintf(stderr, "failed to open %s for writing\n", PPP_CONF);
		EXIT();
		return -1;
	}

	fprintf(fout, "ipparam wan.%d.%d.%d\n", wandev, ift_node->instance, pppc_node->instance);

	memset(&ai, 0, sizeof(struct atm_info_t));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig */
	dslc = tr069_get_table_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_WANDSLLinkConfig);
	if (!dslc) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.DestinationAddress */
	if (!get_atm_da(&ai, tr069_get_string_by_id(dslc,
						    cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_DestinationAddress))) {
		EXIT();
		goto out_error;
	}

	fprintf(fout, "plugin pppoatm.so %d.%d\n", ai.addr.sap_addr.vpi, ai.addr.sap_addr.vci);

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.ATMEncapsulation */
	encap = tr069_get_enum_by_id(dslc, cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_ATMEncapsulation);
	if (encap == 0)
		fprintf(fout, "llc-encaps ");
	else if (encap == 1)
		fprintf(fout, "vc-encaps ");
	else {
		debug("unknown ATMEncapsulation: %d", encap);
		EXIT();
		return -1;
	}

	fprintf(fout, "\n");

	ppp_defaults(fout, pppc);
	fclose(fout);

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection */
	ppp_startif(device,
		    PPP_CONF,
		    (tr069_selector){cwmp__InternetGatewayDevice,
				    cwmp__IGD_WANDevice,
				    wandev,
				    cwmp__IGD_WANDev_i_WANConnectionDevice,
				    ift_node->instance,
				    cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection,
				    pppc_node->instance, 0});

	return 1;

 out_error:
	fclose(fout);
	return 0;
}

/*
 * iterate over all WANxxConnection objects and start them
 */
static int atm_pppoa_ifup(const char *device, const tr069_selector sel, struct tr069_instance_node *ift_node)
{
	int lt;
	struct tr069_value_table *ift = DM_TABLE(ift_node->table);
	struct tr069_instance *wanc;
	struct tr069_value_table *dslc;

	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig */
        if (sel[1] != cwmp__IGD_WANDevice ||
            sel[2] == 0 ||
            sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
            sel[4] == 0) {
                EXIT();
                return 0;
        }

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig */
	dslc = tr069_get_table_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_WANDSLLinkConfig);
	if (!dslc) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection */
	wanc = tr069_get_instance_ref_by_id(ift,cwmp__IGD_WANDev_i_ConDev_j_WANPPPConnection);
	if (wanc) {
		struct tr069_instance_node *node;

		for (node = tr069_instance_first(wanc);
		     node != NULL;
		     node = tr069_instance_next(wanc, node)) {
			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i} */
			struct tr069_value_table *pppc = DM_TABLE(node->table);

			debug("(): pppdev: %d, %p\n", node->instance, pppc);

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.Enabled */
			if (!tr069_get_bool_by_id(pppc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_Enable))
				continue;

			/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANPPPConnection.{i}.ConnectionType */
			lt = tr069_get_enum_by_id(pppc, cwmp__IGD_WANDev_i_ConDev_j_PPPCon_k_ConnectionType);
			debug("(): ConnType: %d\n", lt);
			switch (lt) {
			case 1:               /* IP_Routed */
				/* start PPPoA session */
				pppoa_start_if(device, sel[2], ift_node, node);
				break;

			case 2:               /* DHCP_Spoofed */
			case 4:               /* PPPoE_Relay */
			case 5:               /* PPTP_Relay */
			case 6:               /* L2TP_Relay */
				/* not implemented */

			case 3:               /* PPPoE_Bridged */
				/* forbidden */
			case 0:               /* Unconfigured */
				break;
			}
		}
	}

	EXIT();
	return 1;
}

/*
 * ATM RFC2684 bridged interface
 */
int br2684_ifup(const char *device, const tr069_selector sel)
{
	int rc;


	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	if (sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return 0;
	}

	rc = wan_eth_ifup(device, sel);

	EXIT();
	return rc;
}

/*
 * ATM Classical/IP over ATM (RFC15xx/RFC2684)
 */
int atm_ipoa_ifup(const char *device, const tr069_selector sel)
{
	struct atm_info_t *p;
	int id;
	int rc;


	ENTER();

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	if (sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return 0;
	}


	rc = wan_eth_ifup(device, sel);

	id = ((sel[2] & 0xff) << 8) | (sel[4] & 0xff);

	pthread_mutex_lock(&atm_info_head.mutex);

	list_search(struct atm_info_t, atm_info_head, id, atm_int_cmp, p);
	if (p) {
		const tr069_selector ipsel = { cwmp__InternetGatewayDevice,
					       cwmp__IGD_WANDevice,
					       sel[2],
					       cwmp__IGD_WANDev_i_WANConnectionDevice,
					       sel[4],
					       cwmp__IGD_WANDev_i_ConDev_j_WANIPConnection,
					       1,
					       cwmp__IGD_WANDev_i_ConDev_j_IPCon_k_DefaultGateway, 0 };
		struct in_addr gw;
		char ipaddr_buf[INET_ADDRSTRLEN];

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANIPConnection.{i}.DefaultGateway */
		gw = tr069_get_ipv4_by_selector(ipsel);
		if (gw.s_addr != INADDR_ANY && gw.s_addr != INADDR_NONE)
			vasystem("atmarp -s %s %d.%d.%d",
				 inet_ntop(AF_INET, &gw, ipaddr_buf, INET_ADDRSTRLEN),
				 p->addr.sap_addr.itf, p->addr.sap_addr.vpi, p->addr.sap_addr.vci);
	}
	pthread_mutex_unlock(&atm_info_head.mutex);

	EXIT();
	return rc;
}

int atm_linkdown_all()
{
	struct atm_info_t *p;

	ENTER();

	ppp_stop_all();

	pthread_mutex_lock(&atm_info_head.mutex);
	list_foreach(struct atm_info_t, atm_info_head, p) {
		debug("(): %p, proto: %d, fd: %d\n", p, p->proto, p->fd);
		if ((p->proto == 0 || p->proto == 3) && p->fd > 0) {
			shutdown(p->fd, 2);
			close(p->fd);
			p->fd = -1;
		}
	}

	pthread_mutex_unlock(&atm_info_head.mutex);

	EXIT();
	return 0;
}

static inline int atm_ifnum_cmp(struct atm_info_t *node, int ifnum)
{
	return INTCMP(node->ifnum, ifnum);
}

int br2684_ifdown(const char *device, const tr069_selector sel)
{
	int ifnum;
	struct tr069_value_table *ift;
	struct tr069_value_table *dslc;

	int rc;
	char b[128];

	ENTER();

	debug("(): %s, %s", device, sel2str(b, sel));

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	if (sel[1] != cwmp__IGD_WANDevice ||
	    sel[2] == 0 ||
	    sel[3] != cwmp__IGD_WANDev_i_WANConnectionDevice ||
	    sel[4] == 0) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i} */
	ift = tr069_get_table_by_selector(sel);
	if (!ift) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig */
	dslc = tr069_get_table_by_id(ift, cwmp__IGD_WANDev_i_ConDev_j_WANDSLLinkConfig);
	if (!dslc) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.LinkType */
	switch (tr069_get_int_by_id(dslc, cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_LinkType)) {
		case 0:								/* EoA */
		case 3:								/* PPPoE */
			rc = wan_ifdown(device, sel);
			break;
		case 1:								/* IPoA */
			break;
		case 4:								/* CIP */
			break;
		default:
			break;
	}

#if defined(WITH_BCM63XX)
	{
		struct atm_info_t ai;

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANConnectionDevice.{i}.WANDSLLinkConfig.DestinationAddress */
		if (get_atm_da(&ai, tr069_get_string_by_id(dslc,
							   cwmp__IGD_WANDev_i_ConDev_j_DSLLnkCfg_DestinationAddress))) {
			vasystem("/usr/sbin/atmctl operate vcc --del %d.%d.%d aal5 1 unknown --delq %d.%d.%d 64 0",
				 ai.addr.sap_addr.itf, ai.addr.sap_addr.vpi, ai.addr.sap_addr.vci,
				 ai.addr.sap_addr.itf, ai.addr.sap_addr.vpi, ai.addr.sap_addr.vci);
		}
	}
#endif

	/* remove the device node */
	if (sscanf(device, ATM_BR_DEVICE, &ifnum) == 1) {
		struct atm_info_t *p;

		ENTER();
		pthread_mutex_lock(&atm_info_head.mutex);

		debug(": ifnum: %d\n", ifnum);
		list_search(struct atm_info_t, atm_info_head, ifnum, atm_ifnum_cmp, p);
		debug(": search head: %p\n", atm_info_head.next);
		if (atm_info_head.next)
			debug(": search head: %d\n", atm_info_head.next->id);
		debug(": search: %p\n", p);
		if (p) {
			list_remove(struct atm_info_t, atm_info_head, p);
			atm_info_head.idmap &= ~(1 << ifnum);

			/*
			debug("(): %p, proto: %d, fd: %d\n", p, p->proto, p->fd);
			if ((p->proto == 0 || p->proto == 3) && p->fd > 0) {
				shutdown(p->fd, 2);
				close(p->fd);
			}
			*/
			free(p);
		}
		pthread_mutex_unlock(&atm_info_head.mutex);
		EXIT();
	}

	EXIT();
	return 0;
}
