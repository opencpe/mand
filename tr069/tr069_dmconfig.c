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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <signal.h>

#include <sys/tree.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <netdb.h>

#include <sys/time.h>
#include <event.h>
#include <ev.h>

#include <sys/tree.h>

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#include <talloc/talloc.h>
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/diammsg.h"
#include "libdmconfig/codes.h"

#include "tr069.h"
#include "tr069d.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"
#include "tr069_cache.h"
#include "tr069_serialize.h"
#include "tr069_cfgsessions.h"
#include "tr069_strings.h"
#include "tr069_cfg_bkrst.h"
#include "tr069_notify.h"
#include "tr069_dmconfig.h"
#include "tr069_validate.h"
#include "tr069_ping.h"
#include "tr069_trace.h"
#include "tr069_capture.h"
#include "ifup.h"
#include "firewall.h"
#include "dnsmasq.h"
#include "client.h"
#include "proxy.h"
#include "dhcp.h"
#include "mtd.h"
#include "ftools.h"
#include "utils/binary.h"

#define SDEBUG
#include "debug.h"

#define dm_debug(sid, format, ...) debug(": [#%08X] " format, sid, ## __VA_ARGS__)
#define dm_ENTER(sid) dm_debug(sid, "%s", "enter")
#define dm_EXIT(sid) dm_debug(sid, "%s, %d", "exit", __LINE__)

#define UINT16_DIGITS	6	/* log(2^16-1)+1 */

		/* FIXME: also in tr069_fkts.c */
#define TCPDUMP "/usr/sbin/tcpdump"

		/* workaround: refer to tr069_fkts.c */
extern char tr069_fkts_dummy_dependency;
static char *tr069_fkts_dummy_reference __attribute__((used)) = &tr069_fkts_dummy_dependency;

extern int		firmware_upgrade;
extern pthread_mutex_t	firmware_upgrade_mutex; /* in tr069d.c, protects firmware_upgrade */

		/* in reboot.c */
int sys_shutdown_system(unsigned long magic);

		/* in dhcp_dhcpd.c */
void dhcpinfo(const char *cmd);

static int init_libdmconfig_socket(int type);
static SESSION *lookup_session(uint32_t sessionid);

static void session_times_out(int fd __attribute__((unused)),
			      short type __attribute__((unused)), void *param);
static void requested_session_timeout(int fd __attribute__((unused)),
				      short type __attribute__((unused)), void *param);

static void freeSockCtx(SOCKCONTEXT *sockCtx);
static void async_free_sockCtx(EV_P __attribute__((unused)),
			       ev_async *w, int revents __attribute__((unused)));
static void disableSockCtx(SOCKCONTEXT *sockCtx);
static inline void threadDerefSockCtx(SOCKCONTEXT *sockCtx);

static inline void unsubscribeNotify(SESSION *le);

static DM_RESULT build_client_info(void *ctx, DIAM_AVPGRP **grp,
				   struct tr069_value_table *clnt);

static void acceptEvent(int sfd __attribute__((unused)),
			short event __attribute__((unused)),
			void *arg __attribute__((unused)));
static void readEvent(int fd, short event, void *arg);
static inline int processRequest(SOCKCONTEXT *sockCtx, COMMSTATUS status);
static void writeEvent(int fd, short event, void *arg);

static int register_answer(uint32_t code, uint32_t hopid, uint32_t endid,
			   uint32_t rc, DIAM_AVPGRP *avps, SOCKCONTEXT *sockCtx);
static int register_request(uint32_t code, DIAM_AVPGRP *avps, SOCKCONTEXT *sockCtx);
static int register_packet(DIAM_REQUEST *packet, SOCKCONTEXT *sockCtx);

static int reset_writeEvent(SOCKCONTEXT *sockCtx);
static void async_reset_writeEvent(EV_P __attribute__((unused)),
				   ev_async *w, int revents __attribute__((unused)));

static DIAM_AVPGRP *build_notify_events(struct notify_queue *queue, int level);
static void dmconfig_notify_cb(void *data, struct notify_queue *queue);
static void dmconfig_notify_gw_cb(void *data, struct notify_queue *queue);

static void dmconfig_auth_cb(int res __attribute__((unused)),
			     struct tr069_value_table *clnt, void *data);
static void auth_timeout(int fd __attribute__((unused)),
			 short type __attribute__((unused)), void *data);

static DM_RESULT dmconfig_avp2value(OBJ_AVPINFO *header,
				    const struct tr069_element *elem,
				    DM_VALUE *value);
static DM_RESULT dmconfig_value2avp(GET_GRP_CONTAINER *container,
				    const struct tr069_element *elem,
				    const DM_VALUE val);

static DM_RESULT dmconfig_set_cb(void *data, const tr069_selector sel,
				 const struct tr069_element *elem,
				 struct tr069_value_table *base,
				 const void *value __attribute__((unused)),
				 DM_VALUE *st);
static DM_RESULT dmconfig_get_cb(void *data,
				 const tr069_selector sb __attribute__((unused)),
				 const struct tr069_element *elem,
				 const DM_VALUE val);
static int dmconfig_list_cb(void *data, CB_type type, tr069_id id,
			    const struct tr069_element *elem,
			    const DM_VALUE value __attribute__((unused)));
static DM_RESULT dmconfig_retrieve_enums_cb(void *data,
					    const tr069_selector sb __attribute__((unused)),
					    const struct tr069_element *elem,
					    const DM_VALUE val __attribute__((unused)));

static inline uint32_t process_request_session(struct event_base *base,
					       SOCKCONTEXT *sockCtx,
					       uint32_t diam_code, uint32_t hopid,
					       uint32_t sessionid,
					       DIAM_AVPGRP *grp);
static uint32_t process_start_session(SOCKCONTEXT *sockCtx, uint32_t flags,
				      uint32_t hopid, struct timeval timeout);
static uint32_t process_switch_session(SOCKCONTEXT *sockCtx, uint32_t flags,
				       uint32_t hopid, SESSION *le, struct timeval timeout);
static int process_end_session(uint32_t sessionid);

static inline void doReboot(void);

static void *dmconfig_firmware_upgrade_thread(void *arg __attribute__((unused)));
static void fw_finish(int code, const char *fmt, ...);
static void fw_progress(const char *msg, int state, int total,
			int current, const char *unit);

static void *dmconfig_ping_thread(void *arg __attribute__((unused)));
static int ping_cb(void *ud __attribute__((unused)), int bytes, struct in_addr ip,
		   uint16_t seq, unsigned int triptime);

static void *dmconfig_traceroute_thread(void *arg __attribute__((unused)));
static int traceroute_cb(void *ud __attribute__((unused)), int code, unsigned int hop,
			 const char *hostname, struct in_addr ip, int triptime);

static void *dmconfig_pcap_thread(void *arg __attribute__((unused)));
static void async_abort_pcap(EV_P_ ev_async *w __attribute__((unused)),
			     int revents __attribute__((unused)));

		/* session handling: session list and misc. variables  */

			/* libdmconfig clients get sessionIds in the range of 1 to MAX_INT */
static uint32_t			session_counter;
static uint32_t			cfg_sessionid = 0;	/* 0 means there's no (libdmconfig) configure session */

static int			accept_socket;
static struct event_base	*evbase;

static SESSION			*session_head = NULL;
static REQUESTED_SESSION	*reqsession_head = NULL;
static SOCKCONTEXT		*socket_head = NULL;

static struct event		clientConnection;
int				libdmconfigSocketType;

static uint32_t			req_hopid;
static uint32_t			req_endid;

		/* static as only one of these operations is running at once */

static struct _fwupdate_ctx	fwupdate_ctx;
static struct _ping_ctx		ping_ctx = {.abort_mutex = PTHREAD_MUTEX_INITIALIZER};
static struct _traceroute_ctx	traceroute_ctx = {.abort_mutex = PTHREAD_MUTEX_INITIALIZER};

static int			pcap_running = 0;
static pthread_mutex_t		pcap_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct _pcap_ctx		pcap_ctx;

static pthread_mutex_t		dmconfig_mutex = PTHREAD_MUTEX_INITIALIZER; /* generic dmconfig mutex */

static pthread_t		main_thread;

static SESSION *
lookup_session(uint32_t sessionid)
{
	SESSION *ret;

	dm_ENTER(sessionid);

	if (!sessionid) {
		dm_EXIT(sessionid);
		return NULL;
	}

	for (ret = session_head->next;
			ret && ret->sessionid != sessionid; ret = ret->next);

	dm_EXIT(sessionid);
	return ret;
}

static tr069_id get_first_scg_zone(void)
{
	struct tr069_instance *l;
	struct tr069_instance_node *node;

	l = tr069_get_instance_ref_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0 });
	if (l) {
		node = tr069_instance_first(l);
		if (node)
			return node->instance;
	}

	return TR069_ERR;
}

static int
init_libdmconfig_socket(int type)
{
	int fd;

	ENTER();

			/* binding and listening cannot block */

	if (type == AF_UNIX) {
		static struct sockaddr_un sockaddr;

		if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
			EXIT();
			return -1;
		}

		memset(&sockaddr, 0, sizeof(sockaddr));

		sockaddr.sun_family = AF_UNIX;
		strncpy(sockaddr.sun_path + 1, SERVER_LOCAL,
			sizeof(sockaddr.sun_path) - 1);

		if (bind(fd, &sockaddr, sizeof(struct sockaddr_un))) {
			close(fd);
			EXIT();
			return -1;
		}
	} else { /* AF_INET */
		static struct sockaddr_in sockaddr;
		static int flag = 1;

		if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
			EXIT();
			return -1;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag))) {
			close(fd);
			EXIT();
			return -1;
		}

		memset(&sockaddr, 0, sizeof(sockaddr));

		sockaddr.sin_family = AF_INET;
		sockaddr.sin_port = htons(SERVER_PORT);
		sockaddr.sin_addr.s_addr = htonl(ACCEPT_IP);

		if (bind(fd, &sockaddr, sizeof(struct sockaddr_in))) {
			close(fd);
			EXIT();
			return -1;
		}
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	if (listen(fd, MAX_CONNECTIONS)) {
		close(fd);
		EXIT();
		return -1;
	}

	EXIT();
	return fd;
}

uint8_t
init_libdmconfig_server(struct event_base *base)
{
	SOCKCONTEXT *old_socket_head = socket_head; /* required since this function may be called
						       for cleanup purposes even if threads still depend on some sockCtx
						       in this case we don't want to allocate socket_head or free it after 'abort:' */

	ENTER();

	evbase = base;
	main_thread = pthread_self();

	if ((accept_socket = init_libdmconfig_socket(libdmconfigSocketType)) == -1) {
		EXIT();
		return 1;
	}

	/* initiate session counter & hop2hop/end2end ids (random value between 1 and MAX_INT) */

	srand((unsigned int)time(NULL));
	session_counter = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
	req_hopid = req_endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;

	/* init the list heads / talloc contexts */

	if (!(session_head = talloc(NULL, SESSION)) ||
	    !(reqsession_head = talloc(NULL, REQUESTED_SESSION)) ||
	    (!old_socket_head && !(socket_head = talloc(NULL, SOCKCONTEXT))))
		goto abort;

	memset(session_head, 0, sizeof(SESSION));
	memset(reqsession_head, 0, sizeof(REQUESTED_SESSION));
	memset(socket_head, 0, sizeof(SOCKCONTEXT));

	event_set(&clientConnection, accept_socket, EV_READ | EV_PERSIST,
		  acceptEvent, NULL);
	event_base_set(evbase, &clientConnection);

	if (event_add(&clientConnection, NULL)) /* it listens the whole time, so no timeout */
		goto abort;

	EXIT();
	return 0;

abort:

	talloc_free(session_head);
	talloc_free(reqsession_head);
	if (!old_socket_head)
		talloc_free(socket_head);

	close(accept_socket);
	EXIT();
	return 1;
}

static void
acceptEvent(int sfd __attribute__((unused)), short event __attribute__((unused)),
	    void *arg __attribute__((unused)))
{
	int			fd, flags;

	SOCKCONTEXT		*sockCtx;
	COMMCONTEXT		*readCtx, *writeCtx;

	ENTER();

	if ((fd = accept(accept_socket, NULL, NULL)) == -1) {
		EXIT();
		return;
	}

	flags = 1;
	/* NOTE: this will fail if the socket is not a TCP socket, but that's nothing to worry */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flags, sizeof(flags));

	if ((flags = fcntl(fd, F_GETFL)) == -1 ||
	    fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
		close(fd);
		EXIT();
		return;
	}

	if (!(sockCtx = talloc(socket_head, SOCKCONTEXT))) {
		close(fd);
		EXIT();
		return;
	}
	memset(sockCtx, 0, sizeof(SOCKCONTEXT));

	sockCtx->refcnt = 1;
	sockCtx->fd = fd;

	readCtx = &sockCtx->readCtx;
	writeCtx = &sockCtx->writeCtx;

	event_set(&readCtx->event, fd, EV_READ | EV_PERSIST, readEvent, sockCtx);
	event_base_set(evbase, &readCtx->event);

	event_set(&writeCtx->event, fd, EV_WRITE | EV_PERSIST, writeEvent, sockCtx);
	event_base_set(evbase, &writeCtx->event);

	if (pthread_mutex_init(&sockCtx->lock, NULL) ||
	    event_add(&readCtx->event, NULL)) {	/* currently, no read timeouts */
		talloc_free(sockCtx);		/* unless a request was partially read */
		close(fd);
		EXIT();
		return;
	}

	ev_async_init(&sockCtx->sync, async_reset_writeEvent);
	ev_async_start((struct ev_loop *)evbase, &sockCtx->sync);

	ev_async_init(&sockCtx->free, async_free_sockCtx);
	ev_async_start((struct ev_loop *)evbase, &sockCtx->free);
	sockCtx->free.data = sockCtx;

	LD_INSERT(socket_head, sockCtx);

	EXIT();
}

/*
 * "garbage collect" a sockCtx
 */

static void
freeSockCtx(SOCKCONTEXT *sockCtx)
{
	ENTER();

	pthread_mutex_destroy(&sockCtx->lock);

	ev_async_stop((struct ev_loop *)evbase, &sockCtx->sync);
	ev_async_stop((struct ev_loop *)evbase, &sockCtx->free);

	talloc_free(sockCtx->readCtx.req);

	L_FOREACH(REQUESTED_SESSION, cur, reqsession_head)
		if (cur->sockCtx == sockCtx) {
			REQUESTED_SESSION *prev = cur->prev;

			if ((prev->next = cur->next))
				cur->next->prev = prev;

			event_del(&cur->timeout);
			talloc_free(cur);

			cur = prev;
		}

	shutdown(sockCtx->fd, SHUT_RDWR);
	close(sockCtx->fd);

	if (sockCtx->notifySession)
		unsubscribeNotify(sockCtx->notifySession);

	LD_FREE(sockCtx); /* also frees the answer list & outgoing requests and
			     removes sockCtx from the sockets list */

	EXIT();
}

static void
async_free_sockCtx(EV_P __attribute__((unused)),
		   ev_async *w, int revents __attribute__((unused)))
{
	freeSockCtx((SOCKCONTEXT*)w->data);
}

/*
 * called from the main thread in case of CONNRESETs and related errors
 * to derefernce & possibly "garbage collect" a sockCtx.
 */

static void
disableSockCtx(SOCKCONTEXT *sockCtx)
{
	ENTER();

	pthread_mutex_lock(&sockCtx->lock);

			/* don't bother us with read/write callbacks again */
	event_del(&sockCtx->readCtx.event);
	event_del(&sockCtx->writeCtx.event);

			/* "deinitialize" so threads won't add events again */
	memset(&sockCtx->readCtx.event, 0, sizeof(struct event));
	memset(&sockCtx->writeCtx.event, 0, sizeof(struct event));

	if (!--sockCtx->refcnt) {
		pthread_mutex_unlock(&sockCtx->lock);
		freeSockCtx(sockCtx);
	} else
		pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
}

/*
 * called from non-main threads to derefernce & possibly "garbage collect" a sockCtx.
 * don't care about events since "garbage collection" is only done when the main
 * thread dereferenced the sockCtx and thus already deleted them
 */

static inline void
threadDerefSockCtx(SOCKCONTEXT *sockCtx)
{
	pthread_mutex_lock(&sockCtx->lock);

	if (!--sockCtx->refcnt) {
		pthread_mutex_unlock(&sockCtx->lock);
		ev_async_send((struct ev_loop *)evbase, &sockCtx->free);
	} else
		pthread_mutex_unlock(&sockCtx->lock);
}

static inline void
unsubscribeNotify(SESSION *le)
{
	free_slot(le->notify.slot);
	le->notify.clientSockCtx->notifySession = NULL;
	memset(&le->notify, 0, sizeof(NOTIFY_INFO));
}

static DM_RESULT
build_client_info(void *ctx, DIAM_AVPGRP **grp, struct tr069_value_table *clnt)
{
	const char	*t_str;
	tr069_selector	*t_sel;
	struct in_addr	t_addr;
	ticks_t		t_ticks;
	unsigned int	t_uint;
	uint64_t	t_uint64;
	const binary_t	*t_binary;

	tr069_selector	sel;

	tr069_selcpy(sel, clnt->id);

	/* FIXME: maybe store the Ids in an array and get/encode the values automatically */
	/* TODO: log retrieved values */

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
	if (diam_avpgrp_add_uint16(ctx, grp, AVP_UINT16, 0, VP_TRAVELPING, clnt->id[3]))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
	if (diam_avpgrp_add_uint16(ctx, grp, AVP_UINT16, 0, VP_TRAVELPING, clnt->id[6]))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ClientToken */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ClientToken);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AcctSessionId */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessClass */
	t_sel = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessClass);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass.{i} */
	if (diam_avpgrp_add_uint16(ctx, grp, AVP_UINT16, 0, VP_TRAVELPING, t_sel ? (*t_sel)[6] : 0))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
	t_addr = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress);
	if (diam_avpgrp_add_address(ctx, grp, AVP_ADDRESS, 0, VP_TRAVELPING, AF_INET, &t_addr))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
	t_addr = tr069_get_ipv4_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);
	if (diam_avpgrp_add_address(ctx, grp, AVP_ADDRESS, 0, VP_TRAVELPING, AF_INET, &t_addr))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.RedirectUrl */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RedirectUrl);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.StartTime */
	t_ticks = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_StartTime);
	if (diam_avpgrp_add_time(ctx, grp, AVP_DATE, 0, VP_TRAVELPING, ticks2time(ticks2realtime(t_ticks))))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTimeout */
	t_ticks = tr069_get_ticks_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTimeout);
	if (diam_avpgrp_add_uint32(ctx, grp, AVP_UINT32, 0, VP_TRAVELPING, ticks2time(t_ticks)))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionTime */
	sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionTime;
	sel[8] = 0;
	t_ticks = tr069_get_ticks_by_selector(sel);
	if (diam_avpgrp_add_uint32(ctx, grp, AVP_UINT32, 0, VP_TRAVELPING, ticks2time(t_ticks)))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.OutOctets */
	t_uint64 = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_OutOctets);
	if (diam_avpgrp_add_uint64(ctx, grp, AVP_UINT64, 0, VP_TRAVELPING, t_uint64))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.InOctets */
	t_uint64 = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_InOctets);
	if (diam_avpgrp_add_uint64(ctx, grp, AVP_UINT64, 0, VP_TRAVELPING, t_uint64))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentCircuitId */
	t_binary = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentCircuitId);
	if (diam_avpgrp_add_raw(ctx, grp, AVP_BINARY, 0, VP_TRAVELPING,
				t_binary ? t_binary->data : "", t_binary ? t_binary->len : 0))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AgentRemoteId */
	t_binary = tr069_get_binary_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AgentRemoteId);
	if (diam_avpgrp_add_raw(ctx, grp, AVP_BINARY, 0, VP_TRAVELPING,
				t_binary ? t_binary->data : "", t_binary ? t_binary->len : 0))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ChargeableUserIdentity */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ChargeableUserIdentity);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
	t_uint = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart);
	if (diam_avpgrp_add_uint16(ctx, grp, AVP_UINT16, 0, VP_TRAVELPING, (uint16_t)t_uint))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
	t_uint = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd);
	if (diam_avpgrp_add_uint16(ctx, grp, AVP_UINT16, 0, VP_TRAVELPING, (uint16_t)t_uint))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MonitorTarget */
	t_sel = tr069_get_selector_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MonitorTarget);
	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.MonitoringTarget.{i} */
	if (diam_avpgrp_add_uint16(ctx, grp, AVP_UINT16, 0, VP_TRAVELPING, t_sel ? (*t_sel)[3] : 0))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxInputOctets */
	t_uint64 = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxInputOctets);
	if (diam_avpgrp_add_uint64(ctx, grp, AVP_UINT64, 0, VP_TRAVELPING, t_uint64))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxOutputOctets */
	t_uint64 = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxOutputOctets);
	if (diam_avpgrp_add_uint64(ctx, grp, AVP_UINT64, 0, VP_TRAVELPING, t_uint64))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MaxTotalOctets */
	t_uint64 = tr069_get_uint64_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MaxTotalOctets);
	if (diam_avpgrp_add_uint64(ctx, grp, AVP_UINT64, 0, VP_TRAVELPING, t_uint64))
		return DM_OOM;

	/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AccessGroupId */
	t_str = tr069_get_string_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AccessGroupId);
	if (diam_avpgrp_add_string(ctx, grp, AVP_STRING, 0, VP_TRAVELPING, t_str ? : ""))
		return DM_OOM;

	return DM_OK;
}

static void
readEvent(int fd, short event, void *arg)
{
	SOCKCONTEXT	*sockCtx = arg;

	COMMSTATUS	status;
	uint8_t		alreadyRead = 0;

	debug("(): [%d]: %d", fd, event);

	do {
				/* NOTE: theoretically locking shouldn't be necessary here
				 * since readCtx is only accessed in the main thread and
				 * the read request is a root talloc context
				 */
		pthread_mutex_lock(&sockCtx->lock);
		event_aux_diamRead(fd, event, &sockCtx->readCtx, &alreadyRead, &status);
		pthread_mutex_unlock(&sockCtx->lock);

		debug(": alreadyRead: %d, status: %d", alreadyRead, status);
	} while (processRequest(sockCtx, status));

	EXIT();
}

/*
 * TODO: split processRequest into inline functions (the switch statement) and
 * maybe merge the rest with 'readEvent'
 */

static inline int
processRequest(SOCKCONTEXT *sockCtx, COMMSTATUS status)
{
	COMMCONTEXT		*ctx;

	char			*path = NULL;
	char			*dum = NULL;
	char			*buf = NULL;

	OBJ_GROUP		obj;

	uint32_t		hop2hop;
	uint32_t		end2end;

	OBJ_AVPINFO		header;
	uint32_t		diam_code;

	uint32_t		code = RC_OK;

	struct timeval		timeout;

	memset(&obj, 0, sizeof(obj));

	pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking not necessary here */

	debug("(): [%d]: %d", sockCtx->fd, status);
	ctx = &sockCtx->readCtx;
	obj.req = ctx->req;

	pthread_mutex_unlock(&sockCtx->lock);

	switch (status) {
	case CONNRESET:
		goto reaccept;
	case INCOMPLETE:
		timeout.tv_sec = TIMEOUT_CHUNKS;
		timeout.tv_usec = 0;

		pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking not necessary here */
		if (event_add(&ctx->event, &timeout)) {	/* reduce readEvent's timeout */
			pthread_mutex_unlock(&sockCtx->lock);
			goto server_err;
		}
		pthread_mutex_unlock(&sockCtx->lock);

		EXIT();
		return 0;
	case NOTHING:
		EXIT();
		return 0;
	case COMPLETE:
		break;
	default:	/* ERROR */
		goto server_err;
	}

		/* request read successfully */

	hop2hop = diam_hop2hop_id(&obj.req->packet);
	end2end = diam_end2end_id(&obj.req->packet);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Received %s:\n",
		diam_packet_flags(&obj.req->packet) & CMD_FLAG_REQUEST ?
							"request" : "answer");
	dump_diam_packet(obj.req);
	diam_request_reset_avp(obj.req);
#endif

				/* don't accept client answers currently */
	if (!(diam_packet_flags(&obj.req->packet) & CMD_FLAG_REQUEST)) {
		debug("(): error, not a request");
		goto reaccept;
	}

	if (diam_request_get_avp(obj.req, &header.code, &header.flags,
				 &header.vendor_id, &header.data, &header.len)) {
		debug("(): error, could not decode avp's");
		goto server_err;
	}
	if (header.code != AVP_SESSIONID || header.len != sizeof(uint32_t)) {
		debug("(): error, no or invalid session id");
		goto reaccept;
	}

	obj.sessionid = diam_get_uint32_avp(header.data);
	dm_debug(obj.sessionid, "session");

	if (!diam_request_get_avp(obj.req, &header.code, &header.flags,
				  &header.vendor_id, &header.data,
				  &header.len)) {
		if (header.code != AVP_CONTAINER) {
			debug("(): error, avp is not a container");
			goto reaccept;
		}
		if (!(obj.reqgrp = diam_decode_avpgrp(obj.req, header.data,
						      header.len))) {
			debug("(): error, could no decode avp container");
			goto server_err;
		}
	}

	diam_code = diam_packet_code(&obj.req->packet);

	if (diam_code != CMD_GET_PASSIVE_NOTIFICATIONS && obj.sessionid &&	/* reset_timeout_obj validates the sessionId, too */
	    reset_timeout_obj(obj.sessionid)) {					/* except for POLLs because they don't reset the timeout */
		code = RC_ERR_INVALID_SESSIONID;
		debug("(): error, invalid session id");
	} else {	/* must... not... use... a... GO... TO... */
		switch (diam_code) {
		case CMD_STARTSESSION:
		case CMD_SWITCHSESSION: {
			uint32_t rc;

			if (!(rc = process_request_session(evbase, sockCtx, diam_code, hop2hop, obj.sessionid, obj.reqgrp)))
				goto increase_timeout;
			if (rc == RC_ERR_ALLOC)
				goto server_err;
			goto reaccept;
		}

		case CMD_ENDSESSION:
			dm_debug(obj.sessionid, "CMD: %s... ", "END SESSION");

			if (process_end_session(obj.sessionid))
				code = RC_ERR_INVALID_SESSIONID;

			break;

		case CMD_SESSIONINFO: {
			SESSION *le;

			dm_debug(obj.sessionid, "CMD: %s... ", "GET SESSION INFO");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)) ||
			    diam_avpgrp_add_uint32(obj.req, &obj.answer_grp, AVP_UINT32, 0, VP_TRAVELPING, le->flags))
				goto server_err;

			break;
		}

		case CMD_CFGSESSIONINFO: {
			SESSION *le;

			dm_debug(obj.sessionid, "CMD: %s... ", "GET CONFIGURE SESSION INFO");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!(le = lookup_session(cfg_sessionid))) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)) ||
			    diam_avpgrp_add_uint32(obj.req, &obj.answer_grp, AVP_SESSIONID, 0, VP_TRAVELPING, cfg_sessionid) ||
			    diam_avpgrp_add_uint32(obj.req, &obj.answer_grp, AVP_UINT32, 0, VP_TRAVELPING, le->flags) ||
			    diam_avpgrp_add_timeval(obj.req, &obj.answer_grp, AVP_TIMEVAL, 0, VP_TRAVELPING, le->timeout_session))
				goto server_err;

			break;
		}

		case CMD_SUBSCRIBE_NOTIFY: {
			SESSION		*le;
			int		slot;

			dm_debug(obj.sessionid, "CMD: %s... ", "SUBSCRIBE NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (le->notify.slot || (slot = alloc_slot(dmconfig_notify_cb, le)) == -1) {
				code = RC_ERR_CANNOT_SUBSCRIBE_NOTIFY;
				break;
			}

			le->notify.slot = slot;
			le->notify.clientSockCtx = sockCtx;

			pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking unnecessary here */
			sockCtx->notifySession = le;
			pthread_mutex_unlock(&sockCtx->lock);

			break;
		}

		case CMD_UNSUBSCRIBE_GW_NOTIFY:
		case CMD_UNSUBSCRIBE_NOTIFY: {
			SESSION	*le;

			dm_debug(obj.sessionid, "CMD: UNSUBSCRIBE %sNOTIFY... ",
				 diam_code == CMD_UNSUBSCRIBE_GW_NOTIFY ? "GATEWAY " : "");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			unsubscribeNotify(le);

			break;
		}

		case CMD_SUBSCRIBE_GW_NOTIFY: {
			SESSION		*le;
			int		slot;

			dm_debug(obj.sessionid, "CMD: %s... ", "SUBSCRIBE GATEWAY NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (le->notify.slot || (slot = alloc_slot(dmconfig_notify_gw_cb, le)) == -1) {
				code = RC_ERR_CANNOT_SUBSCRIBE_NOTIFY;
				break;
			}

			le->notify.slot = slot;
			le->notify.clientSockCtx = sockCtx;

			pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking unnecessary here */
			sockCtx->notifySession = le;
			pthread_mutex_unlock(&sockCtx->lock);

			break;
		}

		case CMD_PARAM_NOTIFY: {
			uint32_t	notify;
			SESSION		*le;

			dm_debug(obj.sessionid, "CMD: %s... ", "PARAM NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_BOOL || header.len != sizeof(uint8_t))
				goto reaccept;

			notify = diam_get_uint8_avp(header.data) ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_CONTAINER || !header.len)
				goto reaccept;

			if (!(obj.avpgrp = diam_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

			while (!diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				tr069_selector sb, *sel;

				if (header.code != AVP_PATH)
					goto reaccept;
				if (!header.len) {
					code = RC_ERR_MISC;
					break;
				}

				if (!(path = strndup(header.data, header.len)))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\" (%s)", "PARAM NOTIFY",
					 path, notify == ACTIVE_NOTIFY ? "active" : "passive");

				sel = tr069_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				if (tr069_set_notify_by_selector(sb, le->notify.slot, notify) != DM_OK) {
					code = RC_ERR_MISC;
					break;
				}
			}

			break;
		}

		case CMD_RECURSIVE_PARAM_NOTIFY: {
			uint32_t	notify;
			SESSION		*le;
			tr069_selector	sb, *sel;

			dm_debug(obj.sessionid, "CMD: %s... ", "RECURSIVE PARAM NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_BOOL || header.len != sizeof(uint8_t))
				goto reaccept;

			notify = diam_get_uint8_avp(header.data) ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_CONTAINER || !header.len)
				goto reaccept;

			if (!(obj.avpgrp = diam_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

			if (diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			if (header.code != AVP_PATH)
				goto reaccept;

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"... ", "RECURSIVE PARAM NOTIFY", path);

			sel = tr069_name2sel(*path ? path : "InternetGatewayDevice", &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (tr069_set_notify_by_selector_recursive(sb, le->notify.slot, notify) != DM_OK)
				code = RC_ERR_MISC;

			break;
		}

		case CMD_GATEWAY_NOTIFY: {
			uint32_t	notify;
			SESSION		*le;
			tr069_id	zone = TR069_ERR;
			tr069_id	client = TR069_ERR;

			dm_debug(obj.sessionid, "CMD: %s... ", "GATEWAY NOTIFY");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: le %p, slot: %d", "GATEWAY NOTIFY", le, le->notify.slot);
			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s: code: %d, len: %d", "GATEWAY NOTIFY", header.code, (int)header.len);
			if (header.code != AVP_BOOL || header.len != sizeof(uint8_t))
				goto reaccept;

			notify = diam_get_uint8_avp(header.data) ? ACTIVE_NOTIFY : PASSIVE_NOTIFY;

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s: CONTAINER: code: %d, len: %d", "GATEWAY NOTIFY", header.code, (int)header.len);
			if (header.code != AVP_CONTAINER || !header.len)
				goto reaccept;

			if (!(obj.avpgrp = diam_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

			while (!diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				dm_debug(obj.sessionid, "CMD: %s: got %d", "GATEWAY NOTIFY", header.code);
				switch (header.code) {
				case AVP_GW_ZONE:
					zone = diam_get_int32_avp(header.data);
					break;

				case AVP_GW_CLIENT_ID:
					client = diam_get_int32_avp(header.data);
					break;
				}
			}
			dm_debug(obj.sessionid, "CMD: %s: after while, zone: %d, client: %d", "GATEWAY NOTIFY", zone, client);

			if (zone == TR069_ERR || client == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			tr069_selector sel = {cwmp__InternetGatewayDevice,
					      cwmp__IGD_X_TPLINO_NET_SessionControl,
					      cwmp__IGD_SCG_Zone,
					      0,
					      cwmp__IGD_SCG_Zone_i_Clients,
					      cwmp__IGD_SCG_Zone_i_Clnts_Client,
					      0, 0, 0};

			sel[3] = zone;
			sel[6] = client;

			sel[7] = 0;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);
			sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);
			sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ClientToken;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);
			sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);
			sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);
			sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);
			sel[7] = cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId;
			tr069_set_notify_by_selector(sel, le->notify.slot, notify);

			break;
		}
		case CMD_GET_PASSIVE_NOTIFICATIONS: {
			SESSION			*le;
			struct notify_queue	*queue;

			dm_debug(obj.sessionid, "CMD: %s... ", "GET PASSIVE NOTIFICATIONS");

			if (!(le = lookup_session(obj.sessionid))) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (!le->notify.slot) {
				code = RC_ERR_REQUIRES_NOTIFY;
				break;
			}

			queue = get_notify_queue(le->notify.slot);
			obj.answer_grp = build_notify_events(queue, PASSIVE_NOTIFY);
			if (!obj.answer_grp) {
				/*
				 * NOTE: we cannot discern real errors from empty queues
				 * simply assume it was an empty queue (empty answer grp expected)
				 */
				if (!(obj.answer_grp = new_diam_avpgrp(obj.req)))
					goto server_err;
				break;
			}
			if (!talloc_reference(obj.req, obj.answer_grp))
				goto server_err;

			break;
		}

		case CMD_DB_ADDINSTANCE: {
			tr069_selector	sb, *sel;
			tr069_id	id;

			dm_debug(obj.sessionid, "CMD: %s", "DB ADD INSTANCE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB ADD INSTANCE", path);

			sel = tr069_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;

			id = diam_get_uint16_avp(header.data);

			dm_debug(obj.sessionid, "CMD: %s id = 0x%hX", "DB ADD INSTANCE", id);

			if (!tr069_add_instance_by_selector(sb, &id)) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)))
				goto server_err;
			if (diam_avpgrp_add_uint16(obj.req, &obj.answer_grp, AVP_UINT16, 0,
						   VP_TRAVELPING, id))
				goto server_err;

			break;
		}

		case CMD_DB_DELINSTANCE: {	/* improvised: check whether this is a table */
			tr069_selector sb, *sel;

			dm_debug(obj.sessionid, "CMD: %s", "DB DELETE INSTANCE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB DELETE INSTANCE", path);

			sel = tr069_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (!tr069_del_table_by_selector(sb)) {
				code = RC_ERR_MISC;
				break;
			}

			break;
		}

		case CMD_DB_SET: {	/* iterate grouped AVPs & display changes */
			SET_GRP_CONTAINER container = {
				.header = &header,
				.session = lookup_session(obj.sessionid)
			};

			dm_debug(obj.sessionid, "CMD: %s", "DB SET");

			if (!container.session) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			while (!diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				tr069_selector	sb, *sel;
				DM_RESULT	rc;

				if (header.code != AVP_CONTAINER)
					goto reaccept;

				if (!(obj.avpgrp = diam_decode_avpgrp(obj.req, header.data, header.len)) ||
				    diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
							&header.vendor_id, &header.data, &header.len))
					goto server_err;
				if (header.code != AVP_PATH)
					goto reaccept;
				if (!header.len) {
					code = RC_ERR_MISC;
					break;
				}

				if (!(path = strndup(header.data, header.len)))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB SET", path);

				sel = tr069_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				if (diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
							&header.vendor_id, &header.data, &header.len))
					goto server_err;

				if ((rc = tr069_get_value_ref_by_selector_cb(sb, &container /* ...tweak... */, &container, dmconfig_set_cb)) == DM_OOM)
					goto server_err;
				if (rc != DM_OK) {
					code = RC_ERR_MISC;
					break;
				}
				talloc_free(obj.avpgrp);
			}

			break;
		}
		case CMD_DB_GET: {	/* iterate path AVPs & send answers */
			GET_BY_SELECTOR_CB get_value = cfg_sessionid && obj.sessionid == cfg_sessionid ?
							tr069_cache_get_value_by_selector_cb : tr069_get_value_by_selector_cb;
			GET_GRP_CONTAINER container;

			dm_debug(obj.sessionid, "CMD: %s", "DB GET");

			container.ctx = obj.req;
			if (!(container.grp = new_diam_avpgrp(container.ctx)))
				goto server_err;

			while (!diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				tr069_selector	sb, *sel;
				DM_RESULT	rc;

				if (header.code != AVP_TYPE_PATH  && header.len <= sizeof(uint32_t))
					goto reaccept;

				container.type = diam_get_uint32_avp(header.data);

				if (!(path = strndup((char*)header.data + sizeof(uint32_t), header.len - sizeof(uint32_t))))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\", type: %d", "DB GET", path, container.type);

				sel = tr069_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				if ((rc = get_value(sb, T_ANY, &container, dmconfig_get_cb)) == DM_OOM)
					goto server_err;
				if (rc != DM_OK) {
					code = RC_ERR_MISC;
					break;
				}
			}

			obj.answer_grp = container.grp;

			break;
		}

		case CMD_DB_LIST: {
			LIST_CTX	list_ctx;
			int		level;

			dm_debug(obj.sessionid, "CMD: %s", "DB LIST");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			memset(&list_ctx, 0, sizeof(LIST_CTX));
			list_ctx.ctx = obj.req;
			if (!(list_ctx.grp = new_diam_avpgrp(list_ctx.ctx)))
				goto server_err;

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			level = diam_get_uint16_avp(header.data);
			list_ctx.max_level = level ? : TR069_SELECTOR_LEN;

			dm_debug(obj.sessionid, "CMD: %s %u", "DB LIST", level);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;

			if (header.len) {
				tr069_selector sb, *sel;

				if (!(path = strndup(header.data, header.len)))
					goto server_err;

				dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB LIST", path);

				sel = tr069_name2sel(path, &sb);
				free(path);
				path = NULL;
				if (!sel) {
					code = RC_ERR_MISC;
					break;
				}

				list_ctx.firstone = 1;	/* there has to be a better solution to ignore the first one */
				if (!tr069_walk_by_selector_cb(sb, level ? level + 1 : TR069_SELECTOR_LEN,
							       &list_ctx, dmconfig_list_cb)) {
					code = RC_ERR_MISC;
					break;
				}
			} else {
				/** InternetGatewayDevice */
				if (!tr069_walk_by_selector_cb((tr069_selector) {cwmp__InternetGatewayDevice, 0},
							       list_ctx.max_level, &list_ctx, dmconfig_list_cb)) {
					code = RC_ERR_MISC;
					break;
				}
			}

			obj.answer_grp = list_ctx.grp;

			break;
		}

		case CMD_DB_RETRIEVE_ENUMS: {
			tr069_selector	sb, *sel;
			DM_RESULT	rc;

			dm_debug(obj.sessionid, "CMD: %s", "DB RETRIEVE ENUMS");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB RETRIEVE ENUMS", path);

			sel = tr069_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)))
				goto server_err;

			if ((rc = tr069_get_value_by_selector_cb(sb, T_ENUM, &obj, dmconfig_retrieve_enums_cb)) == DM_OOM)
				goto server_err;
			if (rc != DM_OK) {
				talloc_free(obj.answer_grp);
				obj.answer_grp = NULL;
				code = RC_ERR_MISC;
			}

			break;
		}

		case CMD_DB_DUMP: {
			long tsize;
			size_t r = 0;
			FILE *tf;

			dm_debug(obj.sessionid, "CMD: %s", "DB DUMP");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB DUMP", path);

			tf = tmpfile();
			if (!tf)
				goto server_err;

			if (path && *path)
				tr069_serialize_element(tf, path, S_ALL);
			else
				tr069_serialize_store(tf, S_ALL);

			free(path);
			path = NULL;

			tsize = ftell(tf);
			fseek(tf, 0, SEEK_SET);

			if (!tsize) {
				fclose(tf);
				code = RC_ERR_MISC;
				break;
			}

			buf = malloc(tsize);
			if (buf)
				r = fread(buf, tsize, 1, tf);
			fclose(tf);
			if (r != 1)
				goto server_err;

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)))
				goto server_err;
			if (diam_avpgrp_add_raw(obj.req, &obj.answer_grp, AVP_STRING, 0,
						VP_TRAVELPING, buf, tsize))
				goto server_err;
			free(buf);
			buf = NULL;

			break;
		}

		case CMD_DB_SAVE:			/* saves running config to persistent storage */
			dm_debug(obj.sessionid, "CMD: %s", "DB SAVE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (obj.sessionid == cfg_sessionid &&
			    !cache_is_empty()) {		/* cache not empty */
				code = RC_ERR_MISC;
				break;
			}

			tr069_save();

			break;

		case CMD_DB_COMMIT: {
			SESSION *le;

			/* commits cache to running config and tries to apply changes */
			dm_debug(obj.sessionid, "CMD: %s", "DB COMMIT");

			if (!(le = lookup_session(obj.sessionid)) || obj.sessionid != cfg_sessionid) {
				code = RC_ERR_REQUIRES_CFGSESSION;
				break;
			}

			if (cache_validate()) {
				exec_actions_pre();
				cache_apply(le->notify.slot ? : -1);
				exec_actions();
				exec_pending_notifications();
			} else {
				code = RC_ERR_MISC;
				break;
			}

			break;
		}

		case CMD_DB_CANCEL:
			dm_debug(obj.sessionid, "CMD: %s", "DB CANCEL");

			if (!cfg_sessionid || obj.sessionid != cfg_sessionid) {
				code = RC_ERR_REQUIRES_CFGSESSION;
				break;
			}

			cache_reset();

			break;

		case CMD_DB_FINDINSTANCE: {
			tr069_selector			sb, *sel;
			tr069_id			param;
			DM_VALUE			value;

			struct tr069_instance_node	*inst;

			const struct tr069_table	*kw;
			DM_RESULT			rc;

			dm_debug(obj.sessionid, "CMD: %s", "DB FINDINSTANCE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

					/* parameter/value container */
			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_CONTAINER)
				goto reaccept;
			if (!(obj.avpgrp = diam_decode_avpgrp(obj.req, header.data, header.len)))
				goto server_err;

					/* path of table */
			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DB FINDINSTANCE", path);

			sel = tr069_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel) {
				code = RC_ERR_MISC;
				break;
			}

					/* find table structure */
			if (!(kw = tr069_get_object_table_by_selector(sb))) {
				code = RC_ERR_MISC;
				break;
			}

					/* name of paramter to check (last part of path) */
			if (diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if ((param = tr069_get_element_id_by_name(header.data, header.len, kw)) == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: parameter id: %u", "DB FINDINSTANCE", param);

					/* value to look for (type is AVP code) */
			if (diam_avpgrp_get_avp(obj.avpgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s: value", "DB FINDINSTANCE");
			if ((rc = dmconfig_avp2value(&header, kw->table + param - 1, &value)) == DM_OOM)
				goto server_err;
			if (rc != DM_OK) {
				code = RC_ERR_MISC;
				break;
			}

			inst = find_instance_by_selector(sb, param, kw->table[param - 1].type, &value);
			tr069_free_any_value(kw->table + param - 1, &value);
			if (!inst) {
				code = RC_ERR_MISC;
				break;
			}
			dm_debug(obj.sessionid, "CMD: %s: answer: %u", "DB FINDINSTANCE", inst->instance);

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)))
				goto server_err;
			if (diam_avpgrp_add_uint16(obj.req, &obj.answer_grp, AVP_UINT16, 0,
						   VP_TRAVELPING, inst->instance))
				goto server_err;

			break;
		}

		case CMD_DEV_BOOTSTRAP:
			dm_debug(obj.sessionid, "CMD: %s", "DEV BOOTSTRAP");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			doBootstrap();

			break;

		case CMD_DEV_WANUP:
			dm_debug(obj.sessionid, "CMD: %s", "DEV WANUP");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			wanup();

			break;

		case CMD_DEV_WANDOWN:
			dm_debug(obj.sessionid, "CMD: %s", "DEV WANDOWN");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			wandown();

			break;

		case CMD_DEV_SYSUP:
			dm_debug(obj.sessionid, "CMD: %s", "DEV SYSUP");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			system_up();

			break;

		case CMD_DEV_CONF_SAVE:
			dm_debug(obj.sessionid, "CMD: %s", "DEV CONFSAVE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: DEV CONFSAVE - Remote Server: %s", dum);
			if (save_conf(dum))
				code = RC_ERR_MISC;
			free(dum);
			dum = NULL;

			break;

		case CMD_DEV_CONF_RESTORE:
			dm_debug(obj.sessionid, "CMD: %s", "DEV CONFRESTORE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: DEV CONFRESTORE - Remote Server: %s", dum);
			if (restore_conf(dum))
				code = RC_ERR_MISC;
			free(dum);
			dum = NULL;

			break;

		case CMD_DEV_BOOT:
			dm_debug(obj.sessionid, "CMD: %s", "DEV BOOT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			tr069_boot_notify();

			break;

		case CMD_DEV_GETDEVICE: {
			tr069_selector	sb, *sel;
			const char	*dev;

			dm_debug(obj.sessionid, "CMD: %s", "DEV GETDEVICE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DEV GETDEVICE", path);

			sel = tr069_name2sel(path, &sb);
			free(path);
			path = NULL;
			if (!sel || !(dev = get_if_device(*sel))) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)) ||
			    diam_avpgrp_add_string(obj.req, &obj.answer_grp, AVP_STRING, 0, VP_TRAVELPING, dev))
				goto server_err;

			break;
		}

		case CMD_DEV_HOTPLUG:
			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_HOTPLUGCMD)
				goto reaccept;

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			/* hotplug logging affects startup times and spams the logs, diabled for now
			 * dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DEV HOTPLUG", dum);
			*/

			hotplug(dum);	/* "hotplug" should be rewritten so it doesn't have to parse */
			free(dum);	/* strings and I don't have to pass them (at least encoding/decoding */
			dum = NULL;	/* wouldn't make sense yet) but could use an union-like structure */

			break;

#if defined(WITH_DHCP_DHCPD)
		case CMD_DEV_DHCP_INFO:
			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING)
				goto reaccept;

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s \"%s\"", "DEV DHCP INFO", dum);

			dhcpinfo(dum);
			free(dum);
			dum = NULL;

			break;
#endif

		case CMD_DEV_DHCP_REMOTE:
		case CMD_DEV_DHCP_CIRCUIT: {
			int		af;
			struct in_addr	addr;
			const binary_t	*ret;

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(dum = strndup(header.data, header.len)))
				goto server_err;

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_ADDRESS ||
			    !diam_get_address_avp(&af, &addr, header.data) || af != AF_INET)
				goto reaccept;

			if (diam_code == CMD_DEV_DHCP_REMOTE) {
				dm_debug(obj.sessionid, "CMD: %s: %s dev: \"%s\", addr: %s ", "DEV DHCP", "REMOTE", dum, inet_ntoa(addr));
				ret = dhcp_get_remote_id(dum, addr);
			} else {
				dm_debug(obj.sessionid, "CMD: %s: %s dev: \"%s\", addr: %s ", "DEV DHCP", "CIRCUIT", dum, inet_ntoa(addr));
				ret = dhcp_get_circuit_id(dum, addr);
			}

			free(dum);
			dum = NULL;

			if (ret) {
				if (!(obj.answer_grp = new_diam_avpgrp(obj.req)) ||
				    diam_avpgrp_add_raw(obj.req, &obj.answer_grp, AVP_STRING, 0, VP_TRAVELPING, ret->data, ret->len))
					goto server_err;
			} else
				code = RC_ERR_MISC;

			break;
		}

		case CMD_DEV_DHCPC_RENEW:
		case CMD_DEV_DHCPC_RELEASE:
		case CMD_DEV_DHCPC_RESTART: {
			tr069_selector iface, *iface_p;
			const char *ifname;
			int r;

			dm_debug(obj.sessionid, "CMD: %s (%u)", "DEV DHCPC", diam_code);

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_PATH)
				goto reaccept;
			if (!header.len) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(path = strndup(header.data, header.len)))
				goto server_err;

			dm_debug(obj.sessionid, "CMD: %s (%u): \"%s\"", "DEV DHCPC", diam_code, path);

			iface_p = tr069_name2sel(path, &iface);
			free(path);
			path = NULL;
			if (!iface_p || !(ifname = get_if_device(iface))) {
				code = RC_ERR_MISC;
				break;
			}

			switch (diam_code) {
			case CMD_DEV_DHCPC_RENEW:
				dm_debug(obj.sessionid, "CMD: %s: %s", "DEV DHCPC RENEW", ifname);
				r = signal_udhcpc(ifname, SIGUSR1);
				break;

			case CMD_DEV_DHCPC_RELEASE:
				dm_debug(obj.sessionid, "CMD: %s: %s", "DEV DHCPC RELEASE", ifname);
				r = signal_udhcpc(ifname, SIGUSR2);
				break;

			case CMD_DEV_DHCPC_RESTART:
				dm_debug(obj.sessionid, "CMD: %s: %s", "DEV DHCPC RESTART", ifname);
				if (!(r = stop_udhcpc(ifname)))
					start_udhcpc(ifname);
				break;
			}

			code = r ? RC_ERR_MISC : RC_OK;
			break;
		}

#if defined(WITH_DHCP_DNSMASQ)
		case CMD_DHCP_CLIENT_ACK:
		case CMD_DHCP_CLIENT_RELEASE:
		case CMD_DHCP_CLIENT_EXPIRE: {
			int rc;

			dm_debug(obj.sessionid, "CMD: %s", "DHCP CLIENT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if ((rc = dnsmasq_info(diam_code, &obj)) == RC_SERVER_ERROR)
				goto server_err;
			else if (rc)
				code = RC_ERR_MISC;

			break;
		}
#endif

		case CMD_GW_NEW_CLIENT: {
			tr069_id	zone = TR069_ERR;
			int		af;
			struct in_addr	addr = { .s_addr = INADDR_NONE };
			char		*mac = NULL;
			char		*username = NULL;
			char		*password = NULL;
			char		*useragent = NULL;

			dm_debug(obj.sessionid, "CMD: %s", "GW NEW CLIENT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			while (!diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				dm_debug(obj.sessionid, "got %d", header.code);
				switch (header.code) {
				case AVP_GW_ZONE:
					zone = diam_get_int32_avp(header.data);
					break;

				case AVP_GW_IPADDRESS:
					if (!diam_get_address_avp(&af, &addr, header.data) ||
					    af != AF_INET)
						goto reaccept;
					break;

				case AVP_GW_MACADDRESS:
					if (!(mac = talloc_strndup(obj.req, header.data, header.len)))
						goto server_err;
					dm_debug(obj.sessionid, "mac: %s", mac);
					break;

				case AVP_GW_USERNAME:
					if (!(username = talloc_strndup(obj.req, header.data, header.len)))
						goto server_err;
					dm_debug(obj.sessionid, "username: %s", username);
					break;

				case AVP_GW_PASSWORD:
					if (!(password = talloc_strndup(obj.req, header.data, header.len)))
						goto server_err;
					dm_debug(obj.sessionid, "password: %s", password);
					break;

				case AVP_GW_USERAGENT:
					if (!(useragent = talloc_strndup(obj.req, header.data, header.len)))
						goto server_err;
					break;

				default:
					goto reaccept;
				}
			}
			if (zone == TR069_ERR)
				zone = get_first_scg_zone();
			if (zone == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			if (!hs_update_client(zone, cwmp___IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddressSource_Gateway,
					      addr, mac, username, password,
					      useragent, NULL, NULL, (tr069_selector){0}, 0))
				code = RC_ERR_MISC;

			break;
		}

		case CMD_GW_DEL_CLIENT: {
			tr069_id	zone = TR069_ERR;
			int		af;
			struct in_addr	addr = { .s_addr = INADDR_NONE };

			dm_debug(obj.sessionid, "CMD: %s", "GW DEL CLIENT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			while (!diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				dm_debug(obj.sessionid, "got %d", header.code);
				switch (header.code) {
				case AVP_GW_ZONE:
					zone = diam_get_int32_avp(header.data);
					break;

				case AVP_GW_IPADDRESS:
					if (!diam_get_address_avp(&af, &addr, header.data) ||
					    af != AF_INET)
						goto reaccept;
					break;

				default:
					goto reaccept;
				}
			}
			if (zone == TR069_ERR)
				zone = get_first_scg_zone();
			if (zone == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}
			if (!hs_remove_client(zone, addr, 0))
				code = RC_ERR_MISC;

			break;
		}

		case CMD_GW_CLIENT_SET_ACCESSCLASS: {
			tr069_selector  clnt, *client = NULL;
			char            username[256] = "\0";
			char            accessclass[128] = "\0";
			char            user_agent[256] = "\0";

			dm_debug(obj.sessionid, "CMD: %s", "GW SET CLIENT ACCESS");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			while (!diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				int len;

				dm_debug(obj.sessionid, "got %d", header.code);
				switch (header.code) {
				case AVP_GW_OBJ_ID: {
					char path[128];
					len = header.len < sizeof(path) ? header.len : sizeof(path) - 1;

					strncpy(path, header.data, len);
					path[len] = '\0';
					dm_debug(obj.sessionid, "obj_id: \"%s\"", path);

					client = tr069_name2sel(path, &clnt);
					break;
				}
				case AVP_GW_USERNAME:
					len = header.len < sizeof(username) ? header.len : sizeof(username) - 1;
					strncpy(username, header.data, len);
					username[len] = '\0';
					dm_debug(obj.sessionid, "username: \"%s\"", username);

					break;

				case AVP_GW_ACCESSCLASS:
					len = header.len < sizeof(accessclass) ? header.len : sizeof(accessclass) - 1;
					strncpy(accessclass, header.data, len);
					accessclass[len] = '\0';
					dm_debug(obj.sessionid, "accessclass: %s", accessclass);

					break;

				case AVP_GW_USERAGENT:
					len = header.len < sizeof(user_agent) ? header.len : sizeof(user_agent) - 1;
					strncpy(user_agent, header.data, len);
					user_agent[len] = '\0';
					dm_debug(obj.sessionid, "user_agent: \"%s\"", user_agent);

					break;
				}
			}

			if (!client || scg_set_client_accessclass(clnt, username, accessclass, 0, user_agent))
				code = RC_ERR_MISC;

			break;
		}

		case CMD_GW_CLIENT_REQ_ACCESSCLASS: {
			tr069_selector  clnt, *client = NULL;
			char            username[256] = "\0";
			char            password[256] = "\0";
			char            accessclass[128] = "\0";
			char            user_agent[256] = "\0";
			struct timeval	timeout = {.tv_sec = 30, .tv_usec = 0};

			struct authentication_answer *auth;

			dm_debug(obj.sessionid, "CMD: %s", "GW REQ CLIENT ACCESS");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			while (!diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						    &header.vendor_id, &header.data, &header.len)) {
				int len;

				dm_debug(obj.sessionid, "got %d", header.code);
				switch (header.code) {
				case AVP_GW_OBJ_ID: {
					char path[128];
					len = header.len < sizeof(path) ? header.len : sizeof(path) - 1;
					strncpy(path, header.data, len);
					path[len] = '\0';
					dm_debug(obj.sessionid, "obj_id: \"%s\"", path);

					client = tr069_name2sel(path, &clnt);
					break;
				}
				case AVP_GW_USERNAME:
					len = header.len < sizeof(username) ? header.len : sizeof(username) - 1;
					strncpy(username, header.data, len);
					username[len] = '\0';
					dm_debug(obj.sessionid, "username: \"%s\"", username);

					break;

				case AVP_GW_PASSWORD:
					len = header.len < sizeof(password) ? header.len : sizeof(password) - 1;
					strncpy(password, header.data, len);
					password[len] = '\0';
					dm_debug(obj.sessionid, "password: \"%s\"", password);

					break;

				case AVP_GW_ACCESSCLASS:
					len = header.len < sizeof(accessclass) ? header.len : sizeof(accessclass) - 1;
					strncpy(accessclass, header.data, len);
					accessclass[len] = '\0';
					dm_debug(obj.sessionid, "accessclass: %s", accessclass);

					break;

				case AVP_GW_USERAGENT:
					len = header.len < sizeof(user_agent) ? header.len : sizeof(user_agent) - 1;
					strncpy(user_agent, header.data, len);
					user_agent[len] = '\0';
					dm_debug(obj.sessionid, "user_agent: \"%s\"", user_agent);

					break;

				case AVP_GW_TIMEOUT:
					timeout = diam_get_timeval_avp(header.data);
					if ((!timeout.tv_sec && !timeout.tv_usec) ||
					    timeout.tv_sec > 60) {
						timeout.tv_sec = 60;
						timeout.tv_usec = 0;
					}
					dm_debug(obj.sessionid, "timeout: %d, %d", (int)timeout.tv_sec, (int)timeout.tv_usec);

					break;

				default:
					goto reaccept;
				}
			}

			if (!client) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(auth = talloc(NULL, struct authentication_answer))) {
				code = RC_ERR_ALLOC;
				break;
			}

			auth->sockCtx = sockCtx;
			auth->hopid = hop2hop;

			evtimer_set(&auth->timeout, auth_timeout, auth);
			event_base_set(evbase, &auth->timeout);
			evtimer_add(&auth->timeout, &timeout);

			if (scg_req_client_accessclass(clnt, username, password, accessclass, 0, user_agent, dmconfig_auth_cb, auth)) {
				event_del(&auth->timeout);
				talloc_free(auth);
				code = RC_ERR_MISC;
				break;
			}

			goto increase_timeout; /* do not yet send request answer */
		}

		case CMD_GW_SOL_INFORM: {
			struct tr069_instance		*zonesinst;
			tr069_id			zoneid;
			struct tr069_value_table	*zone;

			struct tr069_value_table	*accessclasses;
			struct tr069_instance		*accessclassinst;
			tr069_id			accessclassid;

			int				af;
			struct in_addr			addr;

			char				mac[32];

			dm_debug(obj.sessionid, "CMD %s", "GW SIGN OF LIFE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone */
			zonesinst = tr069_get_instance_ref_by_selector((tr069_selector) {
				cwmp__InternetGatewayDevice,
				cwmp__IGD_X_TPLINO_NET_SessionControl,
				cwmp__IGD_SCG_Zone, 0
			});
			if (!zonesinst) {
				code = RC_ERR_MISC;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			zoneid = tr069_idm2id(zonesinst, diam_get_uint16_avp(header.data));
			if (zoneid == TR069_ERR)
				zoneid = get_first_scg_zone();
			if (zoneid == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: zone id: %u", "GW SIGN OF LIFE", zoneid);

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
			if (!(zone = hs_get_zone_by_id(zoneid))) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses */
			if (!(accessclasses = tr069_get_table_by_id(zone, cwmp__IGD_SCG_Zone_i_AccessClasses))) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.AccessClasses.AccessClass */
			accessclassinst = tr069_get_instance_ref_by_id(accessclasses, cwmp__IGD_SCG_Zone_i_ACs_AccessClass);
			if (!accessclassinst) {
				code = RC_ERR_MISC;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			accessclassid = tr069_idm2id(accessclassinst, diam_get_uint16_avp(header.data));
			if (accessclassid == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: access class id: %u", "GW SIGN OF LIFE", accessclassid);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_ADDRESS ||
			    !diam_get_address_avp(&af, &addr, header.data) || af != AF_INET)
				goto reaccept;

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_STRING || header.len != 17) {
				code = RC_ERR_MISC;
				break;
			}
			strncpy(mac, header.data, header.len);
			mac[header.len] = '\0';

			dm_debug(obj.sessionid, "CMD: %s: ip: %08X, mac: %s", "GW SIGN OF LIFE",
				 addr.s_addr, mac);

#if 0
			if (!(auth = talloc(NULL, struct sol_answer))) {
				code = RC_ERR_ALLOC;
				break;
			}
			auth->sockCtx = sockCtx;
			auth->hopid = hop2hop;
#endif

			if (!hs_update_client_from_sol(zoneid, accessclassid, addr, mac, NULL, NULL)) {
				code = RC_ERR_MISC;
				break;
			}
			/*
			 * client is in exit-access-class or exit-request-access-class
			 * (if it doesn't require authentication)
			 * don't try to retrieve any authentication result
			 * (it's only logged by sol-triggerd anyways)
			 */

			break;
		}

		case CMD_GW_HEARTBEAT:
			dm_debug(obj.sessionid, "CMD: %s", "GW HEARTBEAT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			heartbeat_proxy();

			break;

		case CMD_GW_GET_ALL_CLIENTS: {
			tr069_id			zone;

			struct tr069_value_table	*znt;
			struct tr069_value_table	*clnts;
			struct tr069_instance		*clnt;

			dm_debug(obj.sessionid, "CMD: %s", "GW GET ALL CLIENTS");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			if ((zone = diam_get_uint16_avp(header.data)) == TR069_ERR)
				zone = get_first_scg_zone();
			if (zone == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: %u", "GW GET ALL CLIENTS", zone);

			znt = hs_get_zone_by_id(zone);
			if (!znt) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients */
			clnts = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Clients);
			if (!clnts) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client */
			clnt = tr069_get_instance_ref_by_id(clnts, cwmp__IGD_SCG_Zone_i_Clnts_Client);
			if (!clnt) {
				code = RC_ERR_MISC;
				break;
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)))
				goto server_err;

			for (struct tr069_instance_node *node = tr069_instance_first(clnt);
			     node; node = tr069_instance_next(clnt, node)) {
				DIAM_AVPGRP *grp;

				if (!(grp = new_diam_avpgrp(obj.answer_grp)) ||
				    build_client_info(obj.answer_grp, &grp, DM_TABLE(node->table)) != DM_OK ||
				    diam_avpgrp_add_avpgrp(obj.req, &obj.answer_grp, AVP_CONTAINER, 0, VP_TRAVELPING, grp))
				    	goto server_err;
			}

			break;
		}

		case CMD_GW_GET_CLIENT: {
			tr069_id			zone;
			int				af;
			struct in_addr			addr;
			DM_VALUE			addr_val;
			uint32_t			addr_type;
			uint16_t			port;

			struct tr069_value_table	*znt;
			struct tr069_value_table	*clnts;
			struct tr069_instance		*clnt;
			struct tr069_instance_node	*node;

			dm_debug(obj.sessionid, "CMD: %s", "GW GET CLIENT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			if ((zone = diam_get_uint16_avp(header.data)) == TR069_ERR)
				zone = get_first_scg_zone();
			if (zone == TR069_ERR) {
				code = RC_ERR_MISC;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			addr_type = header.code;
			if ((addr_type != AVP_GW_IPADDRESS && addr_type != AVP_GW_NATIPADDRESS) ||
			    !diam_get_address_avp(&af, &addr, header.data) || af != AF_INET)
				goto reaccept;
			if (addr.s_addr == INADDR_NONE || addr.s_addr == INADDR_ANY) {
				code = RC_ERR_MISC;
				break;
			}
			addr_val = init_DM_IP4(addr, 0);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len))
				goto server_err;
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t))
				goto reaccept;
			port = diam_get_uint16_avp(header.data);
			if (port && addr_type == AVP_GW_IPADDRESS) {
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: %u %sIP 0x%08X %u", "GW GET CLIENT",
				 zone, addr_type == AVP_GW_NATIPADDRESS ? "NAT " : "", addr.s_addr, port);

			znt = hs_get_zone_by_id(zone);
			if (!znt) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients */
			clnts = tr069_get_table_by_id(znt, cwmp__IGD_SCG_Zone_i_Clients);
			if (!clnts) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client */
			clnt = tr069_get_instance_ref_by_id(clnts, cwmp__IGD_SCG_Zone_i_Clnts_Client);
			if (!clnt) {
				code = RC_ERR_MISC;
				break;
			}

			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.IPAddress */
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
			node = find_instance(clnt, addr_type == AVP_GW_IPADDRESS ? cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_IPAddress
										 : cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress,
					     T_IPADDR4, &addr_val);
			if (!node) {
				code = RC_ERR_MISC;
				break;
			}

			if (port) {
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortStart */
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATPortEnd */
				while (port < tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortStart) ||
				       port > tr069_get_uint_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATPortEnd)) {
					DM_VALUE *next_val;

					/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
					node = tr069_instance_next_idx(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress, node);
					if (!node) {
						code = RC_ERR_MISC;
						goto send_answer;
					}

					/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.NATIPAddress */
					next_val = tr069_get_value_ref_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_NATIPAddress);
					if (tr069_compare_values(T_IPADDR4, next_val, &addr_val)) {
						code = RC_ERR_MISC;
						goto send_answer;
					}
				}
			}

			if (!(obj.answer_grp = new_diam_avpgrp(obj.req)) ||
			    build_client_info(obj.req, &obj.answer_grp, DM_TABLE(node->table)) != DM_OK)
				goto server_err;

			break;
		}

		case CMD_DEV_RESET:
			dm_debug(obj.sessionid, "CMD: %s", "DEV RESET");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			if (unlink(RESET_FILE)) {
				code = RC_ERR_MISC;
				break;
			}

			cpe_needs_reboot = pthread_self();	/* reboots after the read/write session is terminated */

			break;

		case CMD_DEV_REBOOT:
			dm_debug(obj.sessionid, "CMD: %s", "DEV REBOOT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			cpe_needs_reboot = pthread_self();	/* reboots after the read/write session is terminated */

			break;

		case CMD_DEV_FWUPDATE: {
			char		*filename;
			pthread_t	threadid;

			dm_debug(obj.sessionid, "CMD: %s", "DEV FWUPDATE");

			if (!cfg_sessionid || obj.sessionid != cfg_sessionid) {
				code = RC_ERR_REQUIRES_CFGSESSION;
				break;
			}

			pthread_mutex_lock(&firmware_upgrade_mutex);
			if (firmware_upgrade) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				code = RC_ERR_OPERATION_IN_PROGRESS;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				goto server_err;
			}
			if (header.code != AVP_STRING) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				goto reaccept;
			}
			if (!header.len) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				code = RC_ERR_MISC;
				break;
			}

			if (!(filename = strndup(header.data, header.len))) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				goto server_err;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(filename);
				goto server_err;
			}
			if (header.code != AVP_STRING) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(filename);
				goto reaccept;
			}
			if (!header.len) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(filename);
				code = RC_ERR_MISC;
				break;
			}

			if (!(fwupdate_ctx.device = strndup(header.data, header.len))) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(filename);
				goto server_err;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(filename);
				free(fwupdate_ctx.device);
				goto server_err;
			}
			if (header.code != AVP_UINT32 || header.len != sizeof(uint32_t)) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(filename);
				free(fwupdate_ctx.device);
				goto reaccept;
			}

			fwupdate_ctx.flags = diam_get_uint32_avp(header.data);

			dm_debug(obj.sessionid, "CMD: %s \"%s\" \"%s\" %X", "DEV FWUPDATE", filename, fwupdate_ctx.device, fwupdate_ctx.flags);

			fwupdate_ctx.fwstream = fopen(filename, "r");
			free(filename);
			if (!fwupdate_ctx.fwstream) {
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				free(fwupdate_ctx.device);
				code = RC_ERR_MISC;
				break;
			}

			fwupdate_ctx.sockCtx = sockCtx;

					/* tricky locking behaviour: increment refcnt *after* pthread_create,
					   so we don't have to decrement it in an error case, but lock the mutex
					   *before* pthread_create so there is no chance the threads decrements
					   refcnt before we increased it (otherwise it could lead to an early freeSockCtx) */
			pthread_mutex_lock(&sockCtx->lock);

			if (pthread_create(&threadid, NULL, dmconfig_firmware_upgrade_thread, NULL)) {
				pthread_mutex_unlock(&sockCtx->lock);
				fclose(fwupdate_ctx.fwstream);
				free(fwupdate_ctx.device);
				pthread_mutex_unlock(&firmware_upgrade_mutex);
				goto server_err;
			}

			sockCtx->refcnt++;
			pthread_mutex_unlock(&sockCtx->lock);

			pthread_detach(threadid);

			firmware_upgrade = 1;
			pthread_mutex_unlock(&firmware_upgrade_mutex);

			break;
		}

		case CMD_DEV_PING: {
			pthread_t threadid;

			dm_debug(obj.sessionid, "CMD: %s", "DEV PING");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			pthread_mutex_lock(&ping_mutex);
			if (ping_running) {
				pthread_mutex_unlock(&ping_mutex);
				code = RC_ERR_OPERATION_IN_PROGRESS;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&ping_mutex);
				goto server_err;
			}
			if (header.code != AVP_STRING) {
				pthread_mutex_unlock(&ping_mutex);
				goto reaccept;
			}
			if (!header.len) {
				pthread_mutex_unlock(&ping_mutex);
				code = RC_ERR_MISC;
				break;
			}
			if (!(ping_ctx.hostname = strndup(header.data, header.len))) {
				pthread_mutex_unlock(&ping_mutex);
				goto server_err;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(ping_ctx.hostname);
				pthread_mutex_unlock(&ping_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT32 || header.len != sizeof(uint32_t)) {
				free(ping_ctx.hostname);
				pthread_mutex_unlock(&ping_mutex);
				goto reaccept;
			}
			ping_ctx.send_cnt = diam_get_uint32_avp(header.data);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(ping_ctx.hostname);
				pthread_mutex_unlock(&ping_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT32 || header.len != sizeof(uint32_t)) {
				free(ping_ctx.hostname);
				pthread_mutex_unlock(&ping_mutex);
				goto reaccept;
			}
			ping_ctx.timeout = diam_get_uint32_avp(header.data);

			if (!ping_ctx.send_cnt || !ping_ctx.timeout) {
				free(ping_ctx.hostname);
				pthread_mutex_unlock(&ping_mutex);
				code = RC_ERR_MISC;
				break;
			}

			ping_ctx.answer_hop2hop = hop2hop; /* equals end2end */
			ping_ctx.sockCtx = sockCtx;
			ping_ctx.abort = 0;

			dm_debug(obj.sessionid, "CMD: %s \"%s\" %u %u", "DEV PING",
				 ping_ctx.hostname, ping_ctx.send_cnt, ping_ctx.timeout);

				 	/* see above (CMD_DEV_FWUPDATE) */
			pthread_mutex_lock(&sockCtx->lock);

			if (pthread_create(&threadid, NULL, dmconfig_ping_thread, NULL)) {
				pthread_mutex_unlock(&sockCtx->lock);
				free(ping_ctx.hostname);
				pthread_mutex_unlock(&ping_mutex);
				goto server_err;
			}

			sockCtx->refcnt++;
			pthread_mutex_unlock(&sockCtx->lock);

			pthread_detach(threadid);

			ping_running = 1;
			pthread_mutex_unlock(&ping_mutex);

			goto increase_timeout; /* answer registered by thread */
		}

		case CMD_DEV_PING_ABORT: /* FIXME */
			dm_debug(obj.sessionid, "CMD: %s", "DEV PING ABORT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			pthread_mutex_lock(&ping_mutex);
			if (!ping_running) { /* that doesn't even mean dmconfig_ping_thread is running */
				pthread_mutex_unlock(&ping_mutex);
				code = RC_ERR_MISC;
				break;
			}

			pthread_mutex_lock(&ping_ctx.abort_mutex);
			ping_ctx.abort = 1;
			pthread_mutex_unlock(&ping_ctx.abort_mutex);

			pthread_mutex_unlock(&ping_mutex);

			break;

		case CMD_DEV_TRACEROUTE: {
			pthread_t threadid;

			dm_debug(obj.sessionid, "CMD: %s", "DEV TRACEROUTE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			pthread_mutex_lock(&trace_mutex);
			if (trace_running) {
				pthread_mutex_unlock(&trace_mutex);
				code = RC_ERR_OPERATION_IN_PROGRESS;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}
			if (header.code != AVP_STRING) {
				pthread_mutex_unlock(&trace_mutex);
				goto reaccept;
			}
			if (!header.len) {
				pthread_mutex_unlock(&trace_mutex);
				code = RC_ERR_MISC;
				break;
			}
			if (!(traceroute_ctx.hostname = strndup(header.data, header.len))) {
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT8 || header.len != sizeof(uint8_t)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto reaccept;
			}
			traceroute_ctx.tries = diam_get_uint8_avp(header.data);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT32 || header.len != sizeof(uint32_t)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto reaccept;
			}
			traceroute_ctx.timeout = diam_get_uint32_avp(header.data);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto reaccept;
			}
			traceroute_ctx.size = diam_get_uint16_avp(header.data);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT8 || header.len != sizeof(uint8_t)) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto reaccept;
			}
			traceroute_ctx.maxhop = diam_get_uint8_avp(header.data);

			if (!traceroute_ctx.tries ||
			    !traceroute_ctx.timeout || !traceroute_ctx.size ||
			    !traceroute_ctx.maxhop || traceroute_ctx.maxhop > 64) {
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				code = RC_ERR_MISC;
				break;
			}

			traceroute_ctx.answer_hop2hop = hop2hop; /* equals end2end */
			traceroute_ctx.sockCtx = sockCtx;
			traceroute_ctx.abort = 0;

			dm_debug(obj.sessionid, "CMD: %s \"%s\" %u %u %u %u", "DEV TRACEROUTE",
				 traceroute_ctx.hostname, traceroute_ctx.tries, traceroute_ctx.timeout,
				 traceroute_ctx.size, traceroute_ctx.maxhop);

				 	/* see above (CMD_DEV_FWUPDATE) */
			pthread_mutex_lock(&sockCtx->lock);

			if (pthread_create(&threadid, NULL, dmconfig_traceroute_thread, NULL)) {
				pthread_mutex_unlock(&sockCtx->lock);
				free(traceroute_ctx.hostname);
				pthread_mutex_unlock(&trace_mutex);
				goto server_err;
			}

			sockCtx->refcnt++;
			pthread_mutex_unlock(&sockCtx->lock);

			pthread_detach(threadid);

			trace_running = 1;
			pthread_mutex_unlock(&trace_mutex);

			goto increase_timeout; /* answer registered by thread */
		}

		case CMD_DEV_TRACEROUTE_ABORT: /* FIXME */
			dm_debug(obj.sessionid, "CMD: %s", "DEV TRACEROUTE ABORT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			pthread_mutex_lock(&trace_mutex);
			if (!trace_running) { /* that doesn't even mean dmconfig_traceroute_thread is running */
				pthread_mutex_unlock(&trace_mutex);
				code = RC_ERR_MISC;
				break;
			}

			pthread_mutex_lock(&traceroute_ctx.abort_mutex);
			traceroute_ctx.abort = 1;
			pthread_mutex_unlock(&traceroute_ctx.abort_mutex);

			pthread_mutex_unlock(&trace_mutex);

			break;

		/* TODO: several pcap threads would be possible -> dynamically allocate a pcap_ctx
		   also I have to think of a way to identify a particular pcap when aborting
		   (CMD_DEV_PCAP could return the pcap_ctx pointer to the client which uses it as an Id
		    and sends it with CMD_DEV_PCAP_ABORT) */

		case CMD_DEV_PCAP: {
			pthread_t	threadid;
			tr069_selector	*sel;

			dm_debug(obj.sessionid, "CMD: %s", "DEV PACKET CAPTURE");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			pthread_mutex_lock(&pcap_mutex);
			if (pcap_running) {
				pthread_mutex_unlock(&pcap_mutex);
				code = RC_ERR_OPERATION_IN_PROGRESS;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}
			if (header.code != AVP_PATH) {
				pthread_mutex_unlock(&pcap_mutex);
				goto reaccept;
			}
			if (!header.len) {
				pthread_mutex_unlock(&pcap_mutex);
				code = RC_ERR_MISC;
				break;
			}
			if (!(path = strndup(header.data, header.len))) {
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}

			dm_debug(obj.sessionid, "CMD: %s: \"%s\"", "DEV PACKET CAPTURE", path);

			sel = tr069_name2sel(path, &pcap_ctx.interface);
			free(path);
			path = NULL;
			if (!sel) {
				pthread_mutex_unlock(&pcap_mutex);
				code = RC_ERR_MISC;
				break;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}
			if (header.code != AVP_STRING) {
				pthread_mutex_unlock(&pcap_mutex);
				goto reaccept;
			}
			if (!header.len) {
				pthread_mutex_unlock(&pcap_mutex);
				code = RC_ERR_MISC;
				break;
			}
			if (!(pcap_ctx.url = strndup(header.data, header.len))) {
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT32 || header.len != sizeof(uint32_t)) {
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				goto reaccept;
			}
			pcap_ctx.timeout = diam_get_uint32_avp(header.data);

			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
						&header.vendor_id, &header.data, &header.len)) {
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}
			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t)) {
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				goto reaccept;
			}
			pcap_ctx.packets = diam_get_uint16_avp(header.data);

 			if (diam_avpgrp_get_avp(obj.reqgrp, &header.code, &header.flags,
 						&header.vendor_id, &header.data, &header.len)) {
 				free(pcap_ctx.url);
 				pthread_mutex_unlock(&pcap_mutex);
 				goto server_err;
 			}
 			if (header.code != AVP_UINT16 || header.len != sizeof(uint16_t)) {
 				free(pcap_ctx.url);
 				pthread_mutex_unlock(&pcap_mutex);
 				goto reaccept;
 			}
 			pcap_ctx.kbytes = diam_get_uint16_avp(header.data);

			if (!pcap_ctx.timeout ||
			    !pcap_ctx.packets || pcap_ctx.packets > 1024 ||
			    !pcap_ctx.kbytes || pcap_ctx.kbytes > 4096) {
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				code = RC_ERR_MISC;
				break;
			}

			dm_debug(obj.sessionid, "CMD: %s: \"%s\" %u %u %u", "DEV PACKET CAPTURE",
				 pcap_ctx.url, pcap_ctx.timeout, pcap_ctx.packets, pcap_ctx.kbytes);

			pcap_ctx.sockCtx = sockCtx;

			if (!(pcap_ctx.loop = ev_loop_new(0))) {
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}

			ev_async_init(&pcap_ctx.abort, async_abort_pcap);
			ev_async_start(pcap_ctx.loop, &pcap_ctx.abort);

				 	/* see above (CMD_DEV_FWUPDATE) */
			pthread_mutex_lock(&sockCtx->lock);

			if (pthread_create(&threadid, NULL, dmconfig_pcap_thread, NULL)) {
				pthread_mutex_unlock(&sockCtx->lock);
				ev_async_stop(pcap_ctx.loop, &pcap_ctx.abort); /* FIXME: really necessary? */
				ev_loop_destroy(pcap_ctx.loop);
				free(pcap_ctx.url);
				pthread_mutex_unlock(&pcap_mutex);
				goto server_err;
			}

			sockCtx->refcnt++;
			pthread_mutex_unlock(&sockCtx->lock);

			pthread_detach(threadid);

			pcap_running = 1;
			pthread_mutex_unlock(&pcap_mutex);

			break;
		}

		case CMD_DEV_PCAP_ABORT:
			dm_debug(obj.sessionid, "CMD: %s", "DEV PACKET CAPTURE ABORT");

			if (!obj.sessionid) {
				code = RC_ERR_INVALID_SESSIONID;
				break;
			}

			pthread_mutex_lock(&pcap_mutex);
			if (!pcap_running) { /* that doesn't even mean dmconfig_pcap_thread is running */
				pthread_mutex_unlock(&pcap_mutex);
				code = RC_ERR_MISC;
				break;
			}

			ev_async_send(pcap_ctx.loop, &pcap_ctx.abort);

			pthread_mutex_unlock(&pcap_mutex);

			break;

		default:
			dm_debug(obj.sessionid, "CMD: unknown/invalid: %d", diam_code);
			goto reaccept;
		}
	}

	/* FIXME: replace the goto with proper RC code handling */
	/* ie. split up "switch" into separate functions; don't confuse error conditions and error codes sent in answer */

send_answer:

			/* the command evaluation has to set "code" and "answer_grp"
			   (or leave it preinitialized to RC_OK, NULL) */
	if (register_answer(diam_code, hop2hop, end2end, code, obj.answer_grp, sockCtx))
		goto server_err;

increase_timeout:

	pthread_mutex_lock(&sockCtx->lock); /* NOTE: locking unnecessary here */
						/* currently, no read timeouts */
						/* unless a request was partially read */
	if (event_add(&ctx->event, NULL)) {	/* reset readEvent's timeout */
		pthread_mutex_unlock(&sockCtx->lock);
		goto server_err;
	}
	pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
	return 1;

reaccept:		/* protocol/communication errors (including terminated peer connections) */
			/* there's no need to reset everything */

	disableSockCtx(sockCtx);

	EXIT();
	return 0;

server_err:		/* critical error: deallocate everything properly */

	L_FOREACH(SESSION, cur, session_head) {
		if (cur->notify.slot)
			unsubscribeNotify(cur);
		event_del(&cur->timeout);
	}
	talloc_free(session_head);
	session_head = NULL;

	L_FOREACH(REQUESTED_SESSION, cur, reqsession_head)
		event_del(&cur->timeout);
	talloc_free(reqsession_head);
	reqsession_head = NULL;

	L_FOREACH(SOCKCONTEXT, cur, socket_head)
		disableSockCtx(cur);
		/* at least try to free the socket_head if no threads depend on any sockCtx */
	if (!socket_head->next) {
		talloc_free(socket_head);
		socket_head = NULL;
	}

	free(dum);
	free(path);
	free(buf);

	event_del(&clientConnection);
	shutdown(accept_socket, SHUT_RDWR);
	close(accept_socket);

			/* restart server */

	init_libdmconfig_server(evbase);

	EXIT();
	return 0;
}

static void *
dmconfig_firmware_upgrade_thread(void *arg __attribute__((unused)))
{
	SOCKCONTEXT	*sockCtx = fwupdate_ctx.sockCtx;
	int		r, size;

	ENTER();

	fw_callbacks.fw_finish = fw_finish;
	fw_callbacks.fw_progress = fw_progress;

	r = validate_tpfu(fwupdate_ctx.fwstream, &size);
	if (!r || (!(r & ERR_FLAG_MASK) && fwupdate_ctx.flags & CMD_FLAG_FWUPDATE_FORCE)) {
		r = write_firmware(fwupdate_ctx.fwstream, size, fwupdate_ctx.device);
	}

	fw_finish(-1, "done");

			/* it's ok if sockCtx is "collected" immediately, since
			   that's a sign that the main thread already "disabled" it
			   and that the events are already deleted */
	threadDerefSockCtx(sockCtx);

	fclose(fwupdate_ctx.fwstream);
	free(fwupdate_ctx.device);

	if (r) {
		pthread_mutex_lock(&firmware_upgrade_mutex);
		firmware_upgrade = 0;
		pthread_mutex_unlock(&firmware_upgrade_mutex);
	}

	EXIT();
	return NULL;
}

static void
fw_finish(int code, const char *fmt, ...)
{
	SOCKCONTEXT	*sockCtx = fwupdate_ctx.sockCtx;
	va_list		ap;
	char		buf[256];

	DIAM_AVPGRP	*grp;

	ENTER();

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* ignore possible truncation */
	buf[sizeof(buf)-1] = '\0';
	va_end(ap);

	if ((grp = new_diam_avpgrp(NULL)) &&
	    !diam_avpgrp_add_int32(NULL, &grp, AVP_INT32, 0, VP_TRAVELPING, code) &&
	    !diam_avpgrp_add_string(NULL, &grp, AVP_STRING, 0, VP_TRAVELPING, buf))
		register_request(CMD_CLIENT_FWUPDATE_FINISH, grp, sockCtx);

	talloc_free(grp);
	EXIT();
}

static void
fw_progress(const char *msg, int state, int total, int current, const char *unit)
{
	SOCKCONTEXT	*sockCtx = fwupdate_ctx.sockCtx;
	DIAM_AVPGRP	*grp;
	uint32_t	dmstate;

	ENTER();

	switch (state) {
	case STEP_SIGN:		dmstate = FWUPDATE_STEP_SIGN; break;
	case STEP_CRC:		dmstate = FWUPDATE_STEP_CRC; break;
	case STEP_ERASE:	dmstate = FWUPDATE_STEP_ERASE; break;
	case STEP_WRITE:	dmstate = FWUPDATE_STEP_WRITE; break;
	default:		dmstate = FWUPDATE_STEP_UNKNOWN;
	}

	if ((grp = new_diam_avpgrp(NULL)) &&
	    !diam_avpgrp_add_string(NULL, &grp, AVP_STRING, 0, VP_TRAVELPING, msg) &&
	    !diam_avpgrp_add_uint32(NULL, &grp, AVP_FWUPDATE_STEP, 0, VP_TRAVELPING, dmstate) &&
	    !diam_avpgrp_add_int32(NULL, &grp, AVP_INT32, 0, VP_TRAVELPING, current) &&
	    !diam_avpgrp_add_int32(NULL, &grp, AVP_INT32, 0, VP_TRAVELPING, total) &&
	    !diam_avpgrp_add_string(NULL, &grp, AVP_STRING, 0, VP_TRAVELPING, unit))
		register_request(CMD_CLIENT_FWUPDATE_PROGRESS, grp, sockCtx);

	talloc_free(grp);
	EXIT();
}

static void *
dmconfig_ping_thread(void *arg __attribute__((unused)))
{
	SOCKCONTEXT	*sockCtx = ping_ctx.sockCtx;
	struct addrinfo	*addrinfo, hint;

	ENTER();

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;

	if (getaddrinfo(ping_ctx.hostname, NULL, &hint, &addrinfo)) {
		register_answer(CMD_DEV_PING, ping_ctx.answer_hop2hop,
				ping_ctx.answer_hop2hop, RC_ERR_HOSTNAME_RESOLUTION,
				NULL, sockCtx);
	} else if (register_answer(CMD_DEV_PING, ping_ctx.answer_hop2hop,
				   ping_ctx.answer_hop2hop, RC_OK, NULL, sockCtx)) {
		freeaddrinfo(addrinfo);
	} else {
		DIAM_AVPGRP	*grp;

		unsigned int	succ_cnt;
		unsigned int	fail_cnt;
		unsigned int	tavg;
		unsigned int	tmin;
		unsigned int	tmax;

		tr069_ping(*(struct sockaddr_in*)addrinfo->ai_addr,
			   ping_ctx.send_cnt, ping_ctx.timeout,
			   &succ_cnt, &fail_cnt, &tavg, &tmin, &tmax, ping_cb, NULL);

		freeaddrinfo(addrinfo);

		if ((grp = new_diam_avpgrp(NULL)) &&
		    !diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, succ_cnt) &&
		    !diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, fail_cnt) &&
		    !diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, tavg) &&
		    !diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, tmin) &&
		    !diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, tmax))
			register_request(CMD_CLIENT_PING_COMPLETED, grp, sockCtx);
		talloc_free(grp);
	}

	free(ping_ctx.hostname);

			/* see dmconfig_firmware_upgrade_thread */
	threadDerefSockCtx(sockCtx);

	pthread_mutex_lock(&ping_mutex);
	ping_running = 0;
	pthread_mutex_unlock(&ping_mutex);

	EXIT();
	return NULL;
}

static int
ping_cb(void *ud __attribute__((unused)), int bytes, struct in_addr ip,
	uint16_t seq, unsigned int triptime)
{
	SOCKCONTEXT	*sockCtx = ping_ctx.sockCtx;
	DIAM_AVPGRP	*grp;
	int		r;

	ENTER();

	r = !(grp = new_diam_avpgrp(NULL)) ||
	    diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, (uint32_t)bytes) ||
	    diam_avpgrp_add_address(NULL, &grp, AVP_ADDRESS, 0, VP_TRAVELPING, AF_INET, &ip) || /* IP already in network byte order */
	    diam_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, seq) ||
	    diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, triptime) ||
	    register_request(CMD_CLIENT_PING, grp, sockCtx);
	talloc_free(grp);

	pthread_mutex_lock(&ping_ctx.abort_mutex);
	r = r || ping_ctx.abort;
	pthread_mutex_unlock(&ping_ctx.abort_mutex);

	EXIT();
	return r;
}

static void *
dmconfig_traceroute_thread(void *arg __attribute__((unused)))
{
	SOCKCONTEXT	*sockCtx = traceroute_ctx.sockCtx;
	struct addrinfo	*addrinfo, hint;

	ENTER();

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;

	if (getaddrinfo(traceroute_ctx.hostname, NULL, &hint, &addrinfo)) {
		register_answer(CMD_DEV_TRACEROUTE, traceroute_ctx.answer_hop2hop,
				traceroute_ctx.answer_hop2hop, RC_ERR_HOSTNAME_RESOLUTION,
				NULL, sockCtx);
	} else if (register_answer(CMD_DEV_TRACEROUTE, traceroute_ctx.answer_hop2hop,
				   traceroute_ctx.answer_hop2hop, RC_OK, NULL, sockCtx)) {
		freeaddrinfo(addrinfo);
	} else {
		DIAM_AVPGRP		*grp;
		enum tr069_trace_state	r;
		struct sockaddr_in	*addr = (struct sockaddr_in*)addrinfo->ai_addr;

		addr->sin_port = htons(TRACEROUTE_STDPORT);

		r = tr069_trace(*addr, traceroute_ctx.tries, traceroute_ctx.timeout,
				traceroute_ctx.size, traceroute_ctx.maxhop,
				traceroute_cb, NULL);

		freeaddrinfo(addrinfo);

		if ((grp = new_diam_avpgrp(NULL)) &&
		    !diam_avpgrp_add_int32(NULL, &grp, AVP_INT32, 0, VP_TRAVELPING, r))
			register_request(CMD_CLIENT_TRACEROUTE_COMPLETED, grp, sockCtx);
		talloc_free(grp);
	}

	free(traceroute_ctx.hostname);

			/* see dmconfig_firmware_upgrade_thread */
	threadDerefSockCtx(sockCtx);

	pthread_mutex_lock(&trace_mutex);
	trace_running = 0;
	pthread_mutex_unlock(&trace_mutex);

	EXIT();
	return NULL;
}

static int
traceroute_cb(void *ud __attribute__((unused)), enum tr069_trace_state state,
	      unsigned int hop, const char *hostname, struct in_addr ip, int triptime)
{
	SOCKCONTEXT	*sockCtx = traceroute_ctx.sockCtx;
	DIAM_AVPGRP	*grp;
	int		r;

	ENTER();

	r = !(grp = new_diam_avpgrp(NULL)) ||
	    diam_avpgrp_add_int32(NULL, &grp, AVP_INT32, 0, VP_TRAVELPING, state) ||
	    diam_avpgrp_add_uint8(NULL, &grp, AVP_UINT8, 0, VP_TRAVELPING, (uint8_t)hop) ||
	    diam_avpgrp_add_string(NULL, &grp, AVP_STRING, 0, VP_TRAVELPING, hostname ? : "") ||
	    diam_avpgrp_add_address(NULL, &grp, AVP_ADDRESS, 0, VP_TRAVELPING, AF_INET, &ip) || /* IP already in network byte order */
	    diam_avpgrp_add_int32(NULL, &grp, AVP_INT32, 0, VP_TRAVELPING, triptime) ||
	    register_request(CMD_CLIENT_TRACEROUTE, grp, sockCtx);
	talloc_free(grp);

	pthread_mutex_lock(&traceroute_ctx.abort_mutex);
	r = r || traceroute_ctx.abort;
	pthread_mutex_unlock(&traceroute_ctx.abort_mutex);

	EXIT();
	return r;
}

static void *
dmconfig_pcap_thread(void *arg __attribute__((unused)))
{
	enum capLabels {
		PC_COMPLETE = 0,
		ERR_PCAP,
		ERR_TFTP,
		ERR_TFTP_URL
	} ret;

	static const char *dmpfile = "/tmp/dump.cap";
	const char *interface;
	char *hostname, *path;
	int pr, port;

	SOCKCONTEXT	*sockCtx = pcap_ctx.sockCtx;
	DIAM_AVPGRP	*grp;

	ENTER();

	interface = get_if_device(pcap_ctx.interface);

	if ((pr = parse_tftp_url(pcap_ctx.url, &hostname, &path, &port)) < DEFAULTFILE) {
		ret = ERR_TFTP_URL;
		goto errout;
	}

	if (initcap(interface, pcap_ctx.timeout, pcap_ctx.kbytes, pcap_ctx.packets) < 0) {
		ret = ERR_PCAP;
		goto errout;
	}

	cap_start_watchers(pcap_ctx.loop);
	ev_loop(pcap_ctx.loop, 0);
	cap_rem_watchers(pcap_ctx.loop);

	cleancap();

	/*
	 * NOTE: parse_tftp_url() does not permit any character in "hostname" or "path"
	 * that may be used to exploit the shell. It does permit spaces in "path"
	 * though.
	 */
	ret = vasystem("tftp -p -l %s -r \"%s%s\" \"%s\" %d",
		       dmpfile,
		       path, pr == DEFAULTFILE ? dmpfile + 5 : "",
		       hostname, port) ? ERR_TFTP : PC_COMPLETE;
	unlink(dmpfile);

errout:

	free(pcap_ctx.url);

	ev_async_stop(pcap_ctx.loop, &pcap_ctx.abort);
	ev_loop_destroy(pcap_ctx.loop);

	if ((grp = new_diam_avpgrp(NULL)) &&
	    !diam_avpgrp_add_uint32(NULL, &grp, AVP_UINT32, 0, VP_TRAVELPING, ret))
		register_request(CMD_CLIENT_PCAP_ABORTED, grp, sockCtx);
	talloc_free(grp);

			/* see dmconfig_firmware_upgrade_thread */
	threadDerefSockCtx(sockCtx);

	pthread_mutex_lock(&pcap_mutex);
	pcap_running = 0;
	pthread_mutex_unlock(&pcap_mutex);

	EXIT();
	return NULL;
}

static void
async_abort_pcap(EV_P_ ev_async *w __attribute__((unused)),
		 int revents __attribute__((unused)))
{
	debug("(): Stopping capture because of user break.\n");

	ev_unloop(EV_A_ EVUNLOOP_ONE);
}

static inline uint32_t
process_request_session(struct event_base *base, SOCKCONTEXT *sockCtx,
			uint32_t diam_code, uint32_t hopid, uint32_t sessionid,
			DIAM_AVPGRP *grp)
{
	uint32_t	code;
	uint8_t		header_flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	uint32_t	flags;
	SESSION		*le;

	struct timeval	timeout_session;

	dm_ENTER(sessionid);

	switch (diam_code) {
	case CMD_SWITCHSESSION:
		if (!(le = lookup_session(sessionid))) {
			dm_EXIT(sessionid);
			return register_answer(CMD_SWITCHSESSION, hopid,
					       hopid, RC_ERR_INVALID_SESSIONID,
					       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
		}
		break;
	case CMD_STARTSESSION:
		if (sessionid) {
			dm_EXIT(sessionid);
			return register_answer(CMD_STARTSESSION, hopid,
					       hopid, RC_ERR_INVALID_SESSIONID,
					       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
		}

		le = NULL;
	}

	if (diam_avpgrp_get_avp(grp, &code, &header_flags, &vendor_id,
				&data, &len)) {
		dm_EXIT(sessionid);
		return RC_ERR_ALLOC;
	}

	if (code != AVP_UINT32 || len != sizeof(uint32_t)) {
		dm_EXIT(sessionid);
		return RC_ERR_MISC;
	}

	flags = diam_get_uint32_avp(data);

	timeout_session.tv_sec = SESSIONCTX_DEFAULT_TIMEOUT;
	timeout_session.tv_usec = 0;

	while (!diam_avpgrp_get_avp(grp, &code, &header_flags, &vendor_id,
				    &data, &len)) {
		if (len != sizeof(DIAM_TIMEVAL)) {
			dm_EXIT(sessionid);
			return RC_ERR_MISC;
		}

		switch (code) {
		case AVP_TIMEOUT_SESSION:
			timeout_session = diam_get_timeval_avp(data);

			if ((!timeout_session.tv_sec && !timeout_session.tv_usec) ||
			    timeout_session.tv_sec > SESSIONCTX_MAX_TIMEOUT) {
				timeout_session.tv_sec = SESSIONCTX_MAX_TIMEOUT;
				timeout_session.tv_usec = 0;
			}

			break;

		case AVP_TIMEOUT_REQUEST: {
			REQUESTED_SESSION	*session;
			struct timeval		timeout_delay;

			if (!(flags & CMD_FLAG_CONFIGURE) ||
			    getCfgSessionStatus() == CFGSESSION_INACTIVE)
				break;

			timeout_delay = diam_get_timeval_avp(data);

					/* maximum timeout, don't allow an indefinite delay */
			if ((!timeout_delay.tv_sec && !timeout_delay.tv_usec) ||
			    timeout_delay.tv_sec > SESSIONCTX_MAX_TIMEOUT) {
				timeout_delay.tv_sec = SESSIONCTX_MAX_TIMEOUT;
				timeout_delay.tv_usec = 0;
			}

			if (!(session = talloc(reqsession_head,
					       REQUESTED_SESSION))) {
				dm_EXIT(sessionid);
				return RC_ERR_ALLOC;
			}

			LD_INSERT(reqsession_head, session);

			session->flags = flags;
			session->hopid = hopid;
			session->code = diam_code;
			session->sockCtx = sockCtx;
			session->session = le;

			memcpy(&session->timeout_session, &timeout_session,
			       sizeof(struct timeval));

			evtimer_set(&session->timeout, requested_session_timeout,
				    session);
			event_base_set(base, &session->timeout);
			evtimer_add(&session->timeout, &timeout_delay);

			dm_debug(sessionid, "CMD: %s (requested)\n",
			      le ? "SWITCH SESSION" : "START SESSION");

			dm_EXIT(sessionid);
			return RC_OK;
		}

		default:
			dm_EXIT(sessionid);
			return RC_ERR_MISC;
		}
	}

	if (flags & CMD_FLAG_CONFIGURE &&
	    getCfgSessionStatus() != CFGSESSION_INACTIVE) {	/* a config session is already open */
		dm_EXIT(sessionid);
		return register_answer(diam_code, hopid, hopid,
				       RC_ERR_CANNOT_OPEN_CFGSESSION, NULL,
				       sockCtx) ? RC_ERR_ALLOC : RC_OK;
	}

	if (le) {	/* switch sessions only */
		if (flags & CMD_FLAG_CONFIGURE)
			dm_debug(sessionid, "CMD: SWITCH SESSION (r/w to cfg) (id = %08X)\n", le->sessionid);
		else if (le->sessionid == cfg_sessionid)
			dm_debug(sessionid, "CMD: SWITCH SESSION (cfg to r/w) (id = %08X)\n", le->sessionid);
		else {
			dm_EXIT(sessionid);
			return register_answer(CMD_SWITCHSESSION, hopid,
					       hopid, RC_ERR_REQUIRES_CFGSESSION,
					       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
		}

		dm_EXIT(sessionid);
		return process_switch_session(sockCtx, flags, hopid, le,
					      timeout_session);
	}

	debug(": CMD: START SESSION (id = %08X)\n", session_counter);

	dm_EXIT(sessionid);
	return process_start_session(sockCtx, flags, hopid, timeout_session);
}

static uint32_t
process_start_session(SOCKCONTEXT *sockCtx, uint32_t flags, uint32_t hopid,
		      struct timeval timeout)
{
	SESSION		*le;
	DIAM_AVPGRP	*answer;

	uint32_t	rc;

	dm_ENTER(session_counter);

	if (!(le = talloc(session_head, SESSION))) {
		dm_EXIT(session_counter);
		return RC_ERR_ALLOC;
	}
	memset(le, 0, sizeof(SESSION));

	LS_INSERT(session_head, le);

	le->sessionid = session_counter;
	le->flags = flags;

	evtimer_set(&le->timeout, session_times_out, le);
	event_base_set(evbase, &le->timeout);

	memcpy(&le->timeout_session, &timeout, sizeof(struct timeval));
	evtimer_add(&le->timeout, &le->timeout_session);

	if (!(answer = new_diam_avpgrp(NULL)) ||
	    diam_avpgrp_add_uint32(NULL, &answer, AVP_SESSIONID, 0,
				   VP_TRAVELPING, session_counter)) {
		talloc_free(answer);
		dm_EXIT(session_counter);
		return RC_ERR_ALLOC;
	}

	rc = register_answer(CMD_STARTSESSION, hopid, hopid, RC_OK, answer, sockCtx);
	talloc_free(answer);
	if (rc) {
		dm_EXIT(session_counter);
		return RC_ERR_ALLOC;
	}

	if (flags & CMD_FLAG_CONFIGURE) {
		cfg_sessionid = session_counter;
		setCfgSessionStatus(CFGSESSION_ACTIVE_LIBDMCONFIG);
	}

	if (session_counter == MAX_INT)
		session_counter = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
	else
		session_counter++;

	dm_EXIT(le->sessionid);
	return RC_OK;
}

static uint32_t
process_switch_session(SOCKCONTEXT *sockCtx, uint32_t flags,
		       uint32_t hopid, SESSION *le, struct timeval timeout)
{
	dm_ENTER(le->sessionid);

	if (flags & CMD_FLAG_CONFIGURE) {
		cfg_sessionid = le->sessionid;
		setCfgSessionStatus(CFGSESSION_ACTIVE_LIBDMCONFIG);
	} else {
		cfg_sessionid = 0;
		setCfgSessionStatus(CFGSESSION_INACTIVE);
	}

	le->flags = flags;

	memcpy(&le->timeout_session, &timeout, sizeof(struct timeval));
	evtimer_add(&le->timeout, &le->timeout_session);

	dm_EXIT(le->sessionid);
	return register_answer(CMD_SWITCHSESSION, hopid, hopid, RC_OK,
			       NULL, sockCtx) ? RC_ERR_ALLOC : RC_OK;
}

		/* processes another pending config session request or resets the status */

void
processRequestedSessions(void)
{
	REQUESTED_SESSION *session;

	ENTER();

	if (!reqsession_head) {	/* server was not yet initiated */
		EXIT();
		return;
	}

	if (!(session = reqsession_head->next)) {
		cfg_sessionid = 0;
		EXIT();
		return;
	}

	if (session->session) {
		dm_debug(session->session->sessionid, "CFGSESSION TERMINATED: %s", "SWITCH SESSION (r/w to cfg)");

		if (process_switch_session(session->sockCtx, session->flags,
					   session->hopid, session->session,
					   session->timeout_session)) {
			/* fatal error, restart libdmconfig */
			EXIT();
			return;
		}
	} else {
		dm_debug(session_counter, "CFGSESSION TERMINATED: %s", "START SESSION");

		if (process_start_session(session->sockCtx, session->flags,
					  session->hopid, session->timeout_session)) {
			/* fatal error, restart libdmconfig */
			EXIT();
			return;
		}
	}

	event_del(&session->timeout);

	if ((reqsession_head->next = session->next))
		session->next->prev = reqsession_head;

	EXIT();
}

		/* called by CMD_ENDSESSION requests and by timeout events */
static int
process_end_session(uint32_t sessionid) {
	SESSION *cur, *le;

	dm_ENTER(sessionid);

			/* find predecessor of session with sessionid */
	for (cur = session_head;
		cur->next && cur->next->sessionid != sessionid; cur = cur->next);
	le = cur->next;

	if (!le) {
		dm_EXIT(sessionid);
		return 1;
	}
			/* remove from session list */
	cur->next = le->next;

			/* also take care of the pending timeout event */
	evtimer_del(&le->timeout);

	if (le->notify.slot)
		unsubscribeNotify(le);

	talloc_free(le);

	if (sessionid == cfg_sessionid)
		setCfgSessionStatus(CFGSESSION_INACTIVE);
	else {
		exec_actions_pre();
		exec_actions();
		exec_pending_notifications();
	}

	dm_EXIT(sessionid);
	return 0;
}

static int
register_answer(uint32_t code, uint32_t hopid, uint32_t endid,
		uint32_t rc, DIAM_AVPGRP *avps, SOCKCONTEXT *sockCtx)
{
	DIAM_AVPGRP	*completegrp;
	DIAM_REQUEST	*answer;
	int		r;

	ENTER();

	pthread_mutex_lock(&sockCtx->lock);

	debug(": [%d]: %d, rc = %u", sockCtx->fd, code, rc);

	if (!(answer = new_diam_request(sockCtx, code, 0, APP_ID, hopid, endid)) ||
	    !(completegrp = new_diam_avpgrp(answer)) ||
	    diam_avpgrp_add_uint32(answer, &completegrp, AVP_RC, 0,
	    			   VP_TRAVELPING, rc) ||
	    (avps && diam_avpgrp_add_avpgrp(answer, &completegrp, AVP_CONTAINER,
	    				    0, VP_TRAVELPING, avps)) ||
	    build_diam_request(sockCtx, &answer, completegrp)) {
		talloc_free(answer);
		pthread_mutex_unlock(&sockCtx->lock);
		EXIT();
		return 1;
	}

	talloc_free(completegrp);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Send answer:\n");
	dump_diam_packet(answer);
	diam_request_reset_avp(answer);
#endif

	if ((r = register_packet(answer, sockCtx)))
		talloc_free(answer);

	pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
	return r;
}

static int
register_request(uint32_t code, DIAM_AVPGRP *avps, SOCKCONTEXT *sockCtx)
{
	DIAM_REQUEST	*request;
	int		r;

	ENTER();

	pthread_mutex_lock(&sockCtx->lock);
	pthread_mutex_lock(&dmconfig_mutex);

	if (req_hopid == MAX_INT)
		req_hopid = req_endid = (float)rand()/RAND_MAX * (MAX_INT-1) + 1;
	else
		req_hopid = ++req_endid;

	r = !(request = new_diam_request(sockCtx, code, CMD_FLAG_REQUEST,
					 APP_ID, req_hopid, req_endid)) ||
	    build_diam_request(sockCtx, &request, avps);
	pthread_mutex_unlock(&dmconfig_mutex);
	if (r) {
		talloc_free(request);
		pthread_mutex_unlock(&sockCtx->lock);
		EXIT();
		return 1;
	}

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Send request:\n");
	dump_diam_packet(request);
	diam_request_reset_avp(request);
#endif

	if ((r = register_packet(request, sockCtx)))
		talloc_free(request);

	pthread_mutex_unlock(&sockCtx->lock);

	EXIT();
	return r;
}

		/* sockCtx->lock always locked when register_packet is called */
static int
register_packet(DIAM_REQUEST *packet, SOCKCONTEXT *sockCtx)
{
	int r = 0;

	debug(": [%d]: %p", sockCtx->fd, packet);

	packet->info.next = NULL;

	if (!sockCtx->send_queue.tail) {
		/* queue is empty */
		sockCtx->send_queue.head = sockCtx->send_queue.tail = packet;
	} else {
		sockCtx->send_queue.tail->info.next = packet;
		sockCtx->send_queue.tail = packet;
	}

	if (pthread_equal(pthread_self(), main_thread))
		r = reset_writeEvent(sockCtx);
	else
		ev_async_send((struct ev_loop *)evbase, &sockCtx->sync);

	EXIT();
	return r;
}

static int
reset_writeEvent(SOCKCONTEXT *sockCtx)
{
	COMMCONTEXT	*ctx = &sockCtx->writeCtx;
	int		r = 0;

	ENTER();

	if (event_initialized(&ctx->event) &&				/* don't add the event if it was deleted due to a CONNRESET/reaccept */
	    !event_pending(&ctx->event, EV_WRITE | EV_PERSIST, NULL)) {	/* ensures that we don't overwrite its current timeout */
		struct timeval timeout = {
			.tv_sec = TIMEOUT_WRITE_REQUESTS,
			.tv_usec = 0
		};

		r = event_add(&ctx->event, &timeout);
	}

	EXIT();
	return r;
}

static void
async_reset_writeEvent(EV_P __attribute__((unused)),
		       ev_async *w, int revents __attribute__((unused)))
{
	SOCKCONTEXT *sockCtx = (SOCKCONTEXT *)w;

			/* NOTE: theoretically locking shouldn't be necessary here
			 * since the write event is only accessed in the main thread
			 */
	pthread_mutex_lock(&sockCtx->lock);
	reset_writeEvent(sockCtx);
	pthread_mutex_unlock(&sockCtx->lock);
}

static void
writeEvent(int fd, short event, void *arg)
{
	SOCKCONTEXT	*sockCtx = arg;
	COMMCONTEXT	*ctx;
	COMMSTATUS	status = COMPLETE;

	struct timeval	timeout;

	debug(": [%d]: %d", fd, event);

	pthread_mutex_lock(&sockCtx->lock);

	ctx = &sockCtx->writeCtx;

	for (;;) {
		if (!ctx->req) {
			ctx->req = sockCtx->send_queue.head;
			if (!ctx->req) {
				/* queue was empty */
				pthread_mutex_unlock(&sockCtx->lock);
				EXIT();	/* FIXME (and below): more extensive cleanup */
				return;
			}

			sockCtx->send_queue.head = ctx->req->info.next;
			ctx->req->info.next = NULL;

			if (!sockCtx->send_queue.head)
				/* queue is now empty, we dequeued the tail packet */
				sockCtx->send_queue.tail = NULL;
		}

		debug(": [%d]: %p", fd, ctx->req);
		event_aux_diamWrite(fd, event, ctx, &status);
		debug(": [%d]: status: %d", fd, status);

		switch (status) {
		case COMPLETE: {
			uint32_t code = diam_packet_code(&ctx->req->packet);

			if (code == CMD_ENDSESSION || code == CMD_SWITCHSESSION)
				doReboot();

			talloc_free(ctx->req);
			ctx->req = NULL;
			ctx->buffer = NULL;

			if (!sockCtx->send_queue.head) {
				event_del(&ctx->event);
				pthread_mutex_unlock(&sockCtx->lock);
				EXIT();
				return;
			}

			timeout.tv_sec = TIMEOUT_WRITE_REQUESTS;
			timeout.tv_usec = 0;

			if (event_add(&ctx->event, &timeout)) {	/* increase writeEvent's timeout */
				pthread_mutex_unlock(&sockCtx->lock);
				EXIT();
				return;
			}

			break;
		}
		case INCOMPLETE:
			timeout.tv_sec = TIMEOUT_CHUNKS;
			timeout.tv_usec = 0;

			event_add(&ctx->event, &timeout);	/* reduce writeEvent's timeout */
		case NOTHING:
			pthread_mutex_unlock(&sockCtx->lock);
			EXIT();
			return;
		default:	/* connection reset or error */
			pthread_mutex_unlock(&sockCtx->lock);
			disableSockCtx(sockCtx);

			if (status == ERROR) {
				debug(": [%d]: error", fd);
				event_del(&clientConnection);
				shutdown(accept_socket, SHUT_RDWR);
				close(accept_socket);

				/* this is almost certainly wrong */
				init_libdmconfig_server(evbase);
			}

			EXIT();
			return;
		}
	}

	/* shouldn't be reached */
	EXIT();
}

/*
	session timeout cb function
*/

static void
session_times_out(int fd __attribute__((unused)),
		  short type __attribute__((unused)), void *param)
{
	SESSION *le = param;
	uint32_t sessionid = le->sessionid;

	dm_ENTER(sessionid);
	dm_debug(sessionid, "SESSION TIMEOUT: END SESSION");

			/* ignore return value - if the sessionId was already invalid,
			   it's unnecessary to terminate it */
	process_end_session(sessionid);

	doReboot();

	dm_EXIT(sessionid);
}

static void
requested_session_timeout(int fd __attribute__((unused)),
			  short type __attribute__((unused)), void *param)
{
	REQUESTED_SESSION *session = param;

	ENTER();

	debug(": %s SESSION (requested) timed out\n",
	      session->session ? "SWITCH" : "START");

	if (register_answer(session->code, session->hopid, session->hopid,
			    RC_ERR_CANNOT_OPEN_CFGSESSION, NULL, session->sockCtx)) {
		EXIT();
		return;
	}

	LD_FREE(session);

	EXIT();
}

int
reset_timeout_obj(uint32_t sessionid)
{
	SESSION *le;

	dm_ENTER(sessionid);

	if (!(le = lookup_session(sessionid))) {
		EXIT();
		return 1;
	}

	evtimer_add(&le->timeout, &le->timeout_session);

	dm_EXIT(sessionid);
	return 0;
}

static DIAM_AVPGRP *
build_notify_events(struct notify_queue *queue, int level)
{
	struct notify_item	*next;

	DIAM_AVPGRP		*grp;
	int			haveEvent = 0;

	ENTER(": level=%d", level);

	if (!(grp = new_diam_avpgrp(NULL))) {
		EXIT();
		return NULL;
	}

	for (struct notify_item *item = RB_MIN(notify_queue, queue);
	     item;
	     item = next) {
		char			buffer[MAX_PARAM_NAME_LEN];
		char			*path;

		DIAM_AVPGRP		*event;

		next = RB_NEXT(notify_queue, queue, item);

		if (item->level != level)
			continue;

			/* active notification */

		haveEvent = 1;

		if (!(path = tr069_sel2name(item->sb, buffer, sizeof(buffer))) ||
		    !(event = new_diam_avpgrp(grp))) {
			talloc_free(grp);
			EXIT();
			return NULL;
		}

		switch (item->type) {
		case NOTIFY_ADD:
			debug(": instance added: %s", path);

			if (diam_avpgrp_add_uint32(grp, &event, AVP_NOTIFY_TYPE, 0,
						   VP_TRAVELPING,
						   NOTIFY_INSTANCE_CREATED) ||
			    diam_avpgrp_add_string(grp, &event, AVP_PATH, 0,
			    	    		   VP_TRAVELPING, path)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}
			break;

		case NOTIFY_DEL:
			debug(": instance removed: %s", path);

			if (diam_avpgrp_add_uint32(grp, &event, AVP_NOTIFY_TYPE, 0,
						   VP_TRAVELPING,
						   NOTIFY_INSTANCE_DELETED) ||
			    diam_avpgrp_add_string(grp, &event, AVP_PATH, 0,
			    	    		   VP_TRAVELPING, path)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}
			break;

		case NOTIFY_CHANGE: {
			GET_GRP_CONTAINER container = {
				.ctx = event,
				.type = AVP_UNKNOWN
			};
			struct tr069_element *elem;

			debug(": parameter changed: %s", path);

			if (diam_avpgrp_add_uint32(grp, &event, AVP_NOTIFY_TYPE, 0,
						   VP_TRAVELPING,
						   NOTIFY_PARAMETER_CHANGED)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}

			if (!(container.grp = new_diam_avpgrp(container.ctx)) ||
			    tr069_get_element_by_selector(item->sb, &elem) == T_NONE ||
			    dmconfig_value2avp(&container, elem, item->value) != DM_OK) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}

			if (diam_avpgrp_add_uint32_string(grp, &event, AVP_TYPE_PATH, 0,
							  VP_TRAVELPING,
							  container.type, path) ||
			    diam_avpgrp_insert_avpgrp(grp, &event, container.grp)) {
				talloc_free(grp);
				EXIT();
				return NULL;
			}
			break;
		}
		}

		if (diam_avpgrp_add_avpgrp(NULL, &grp, AVP_CONTAINER, 0,
					   VP_TRAVELPING, event)) {
			talloc_free(grp);
			EXIT();
			return NULL;
		}

		talloc_free(event);
		RB_REMOVE(notify_queue, queue, item);
		free(item);
	}

	if (!haveEvent) {
		talloc_free(grp);
		EXIT();
		return NULL;
	}

	EXIT();
	return grp;
}

static void
dmconfig_notify_cb(void *data, struct notify_queue *queue)
{
	SESSION			*session = data;
	NOTIFY_INFO		*notify = &session->notify;

	DIAM_AVPGRP		*grp, *dummy;
	int			r;

	dm_ENTER(session->sessionid);

	grp = build_notify_events(queue, ACTIVE_NOTIFY);
	if (!grp) {
		dm_EXIT(session->sessionid);
		return;
	}
	if (!(dummy = new_diam_avpgrp(NULL))) {
		talloc_free(grp);
		dm_EXIT(session->sessionid);
		return;
	}

	r = diam_avpgrp_add_avpgrp(NULL, &dummy, AVP_CONTAINER, 0,
				   VP_TRAVELPING, grp);
	talloc_free(grp);
	if (r) {
		talloc_free(dummy);
		dm_EXIT(session->sessionid);
		return;
	}

	register_request(CMD_CLIENT_ACTIVE_NOTIFY, dummy, notify->clientSockCtx);

	talloc_free(dummy);
	dm_EXIT(session->sessionid);
}

static void
dmconfig_notify_gw_cb(void *data, struct notify_queue *queue)
{
	SESSION			*session = data;
	NOTIFY_INFO		*notify = &session->notify;

	struct notify_item	*next;
	tr069_id		 zone = 0;
	tr069_id		 client = 0;
	int			 do_notify = 0;
	DIAM_AVPGRP		*dummy;
	DIAM_AVPGRP		*reqg;
	DIAM_AVPGRP		*grp = NULL;

#if defined(SDEBUG)
	char b1[128];
#endif

	dm_ENTER(session->sessionid);

	if (!(dummy = new_diam_avpgrp(NULL)) ||
	    !(reqg = new_diam_avpgrp(dummy))) {
		talloc_free(dummy);
		dm_EXIT(session->sessionid);
		return;
	}

	for (struct notify_item *item = RB_MIN(notify_queue, queue);
	     item;
	     item = next) {

		next = RB_NEXT(notify_queue, queue, item);

		if (item->level == PASSIVE_NOTIFY)
			continue;

			/* active notification */

		if (item->type == NOTIFY_ADD)
			/* cannot handle client instance creations */
			goto continue_remove;

		/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
		if (item->sb[0] != cwmp__InternetGatewayDevice ||
		    item->sb[1] != cwmp__IGD_X_TPLINO_NET_SessionControl ||
		    item->sb[2] != cwmp__IGD_SCG_Zone ||
		    item->sb[3] == 0 ||
		    item->sb[4] != cwmp__IGD_SCG_Zone_i_Clients ||
		    item->sb[5] != cwmp__IGD_SCG_Zone_i_Clnts_Client ||
		    item->sb[6] == 0) {
			dm_debug(session->sessionid, "got notify for non client object: %s\n",
			      sel2str(b1, item->sb));

			goto continue_remove;
		}

		dm_debug(session->sessionid, "notify for client object: %s\n",
			 sel2str(b1, item->sb));

		if (zone != item->sb[3] || client != item->sb[6]) {
			/* new client */

			if (do_notify && grp) {
				/* push notify for old client */
				diam_avpgrp_add_avpgrp(dummy, &reqg,
						       AVP_CONTAINER, 0,
						       VP_TRAVELPING, grp);
				talloc_free(grp);
				grp = NULL;
			}

			zone = item->sb[3];
			client = item->sb[6];
			do_notify = 0;
		}

		switch (item->sb[7]) {
		case 0:
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress:
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ClientToken:
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId:
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId:
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username:
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId:
			do_notify++;
		}

		if (do_notify == 1) {
			grp = new_diam_avpgrp(reqg);
			if (grp) {
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i} */
				diam_avpgrp_add_uint32(reqg, &grp, AVP_GW_ZONE,
						       0, VP_TRAVELPING, zone);
				/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i} */
				diam_avpgrp_add_uint32(reqg, &grp,
						       AVP_GW_CLIENT_ID, 0,
						       VP_TRAVELPING, client);
			}
		}
		switch (item->sb[7]) {
		case 0:
			diam_avpgrp_add_uint32(reqg, &grp, AVP_GW_REMOVED,
					       0, VP_TRAVELPING, 1);
			break;

		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_MACAddress:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.MACAddress */
			if (DM_STRING(item->value))
				diam_avpgrp_add_string(reqg, &grp,
						       AVP_GW_MACADDRESS, 0,
						       VP_TRAVELPING,
						       DM_STRING(item->value));
			break;
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ClientToken:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ClientToken */
			if (DM_STRING(item->value))
				diam_avpgrp_add_string(reqg, &grp, AVP_GW_TOKEN,
						       0, VP_TRAVELPING,
						       DM_STRING(item->value));
			break;
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AcctSessionId:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AcctSessionId */
			if (DM_STRING(item->value))
				diam_avpgrp_add_string(reqg, &grp,
						       AVP_GW_ACCTSESSIONID, 0,
						       VP_TRAVELPING,
						       DM_STRING(item->value));
			break;
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_SessionId:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.SessionId */
			if (DM_STRING(item->value))
				diam_avpgrp_add_string(reqg, &grp,
						       AVP_GW_SESSIONID, 0,
						       VP_TRAVELPING,
						       DM_STRING(item->value));
			break;
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_Username:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.Username */
			if (DM_STRING(item->value))
				diam_avpgrp_add_string(reqg, &grp,
						       AVP_GW_USERNAME, 0,
						       VP_TRAVELPING,
						       DM_STRING(item->value));
			break;
		case cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LocationId:
			/** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LocationId */
			if (DM_STRING(item->value))
				diam_avpgrp_add_string(reqg, &grp,
						       AVP_GW_LOCATIONID, 0,
						       VP_TRAVELPING,
						       DM_STRING(item->value));
			break;
		}

continue_remove:
		RB_REMOVE(notify_queue, queue, item);
		free(item);
	}
	if (do_notify && grp) {
		/* push notify for old client */
		diam_avpgrp_add_avpgrp(dummy, &reqg, AVP_CONTAINER, 0,
				       VP_TRAVELPING, grp);
		talloc_free(grp);
		grp = NULL;
	}

	if (diam_avpgrp_add_avpgrp(NULL, &dummy, AVP_CONTAINER, 0,
				   VP_TRAVELPING, reqg)) {
		talloc_free(dummy);
		dm_EXIT(session->sessionid);
		return;
	}

	register_request(CMD_CLIENT_GATEWAY_NOTIFY, dummy, notify->clientSockCtx);

	talloc_free(dummy);
	dm_EXIT(session->sessionid);
}

static void
dmconfig_auth_cb(int res __attribute__((unused)),
		 struct tr069_value_table *clnt, void *data)
{
	struct authentication_answer *auth = data;

	struct tr069_instance *inst;
	struct tr069_instance_node *node;

	int		reqState, authResult;
	unsigned int	replyCode;

	uint32_t	code = RC_OK;
	DIAM_AVPGRP	*answer, *messages;

	ENTER();

	if (!auth->sockCtx) { /* timeout already occurred */
		talloc_free(auth);
		EXIT();
		return;
	}

	if (!clnt) { /* client session deleted while waiting for RADIUS response */
		code = RC_ERR_MISC;
		goto register_answer;
	}

	/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.AuthenticationRequestState */
	reqState = tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_AuthenticationRequestState);

	/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAuthorizationResult */
	authResult = tr069_get_enum_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_LastAuthorizationResult);

	/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.X_TPOSS_ReplyCode */
	replyCode = tr069_get_uint_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_X_TPOSS_ReplyCode);

	if (!(answer = new_diam_avpgrp(auth)) ||
	    diam_avpgrp_add_int32(auth, &answer, AVP_ENUMID, 0, VP_TRAVELPING, reqState) ||
	    diam_avpgrp_add_int32(auth, &answer, AVP_ENUMID, 0, VP_TRAVELPING, authResult) ||
	    diam_avpgrp_add_uint32(auth, &answer, AVP_UINT32, 0, VP_TRAVELPING, replyCode)) {
		code = RC_ERR_ALLOC;
		goto register_answer;
	}

	/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ReplyMessage */
	if (!(inst = tr069_get_instance_ref_by_id(clnt, cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_ReplyMessage))) {
		code = RC_ERR_MISC;
		goto register_answer;
	}

	if ((node = tr069_instance_first(inst))) {
		if (!(messages = new_diam_avpgrp(answer))) {
			code = RC_ERR_ALLOC;
			goto register_answer;
		}

		do {
			/** InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.ReplyMessage.{i}.Message */
			const char *msg = tr069_get_string_by_id(DM_TABLE(node->table), cwmp__IGD_SCG_Zone_i_Clnts_Clnt_j_RplM_k_Message);

			if (msg && diam_avpgrp_add_string(answer, &messages, AVP_STRING, 0, VP_TRAVELPING, msg)) {
				code = RC_ERR_ALLOC;
				goto register_answer;
			}
		} while ((node = tr069_instance_next(inst, node)));

		if (diam_avpgrp_add_avpgrp(auth, &answer, AVP_CONTAINER, 0, VP_TRAVELPING, messages)) {
			code = RC_ERR_ALLOC;
			goto register_answer;
		}
	}

register_answer:

	register_answer(CMD_GW_CLIENT_REQ_ACCESSCLASS, auth->hopid, auth->hopid,
			code, code == RC_OK ? answer : NULL, auth->sockCtx);
	event_del(&auth->timeout);
	talloc_free(auth);
	EXIT();
}

static void
auth_timeout(int fd __attribute__((unused)),
	     short type __attribute__((unused)), void *data)
{
	struct authentication_answer *auth = data;

	ENTER();

	register_answer(CMD_GW_CLIENT_REQ_ACCESSCLASS, auth->hopid,
			auth->hopid, RC_ERR_TIMEOUT, NULL, auth->sockCtx);
	auth->sockCtx = NULL; /* signals dmconfig_auth_cb that the answer shouldn't be sent again */

	EXIT();
}

#if 0
static void
dmconfig_sol_auth_cb(int authRes, struct tr069_value_table *clnt __attribute__((unused)), void *data)
{
	struct sol_answer *auth = (struct sol_answer *)data;

	uint32_t	code = RC_OK;
	DIAM_AVPGRP	*answer;

	ENTER();

	if (!(answer = new_diam_avpgrp(auth)) ||
	    /** VAR: InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.{i}.Clients.Client.{i}.LastAuthenticationResult */
	    diam_avpgrp_add_int32(auth, &answer, AVP_ENUMID, 0, VP_TRAVELPING, authRes)) {
		code = RC_ERR_ALLOC;
	}

	register_answer(CMD_GW_SOL_INFORM, auth->hopid, auth->hopid,
			code, code == RC_OK ? answer : NULL, auth->sockCtx);
	talloc_free(auth);

	EXIT();
}
#endif

static DM_RESULT
dmconfig_avp2value(OBJ_AVPINFO *header, const struct tr069_element *elem,
		   DM_VALUE *value)
{
	char		*dum = NULL;
	DM_RESULT	r = DM_OK;

	ENTER();

	if (!elem) {
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	memset(value, 0, sizeof(DM_VALUE));

	if (header->code == AVP_UNKNOWN) {
		if (!(dum = strndup(header->data, header->len))) {
			EXIT();
			return DM_OOM;
		}

		switch (elem->type) {
		case T_BASE64:
		case T_BINARY: {	/* tr069_string2value cannot be used since it treats T_BASE64 and T_BINARY differently */
			unsigned int len;
			binary_t *n;

			/* this is going to waste some bytes.... */
			len = ((header->len + 4) * 3) / 4;

			n = malloc(sizeof(binary_t) + len);
			if (!n) {
				r = DM_OOM;
				break;
			}

			debug(": base64 string: %d, buffer: %u", (int)header->len, len);
			n->len = dm_from64((unsigned char *)dum, (unsigned char *)n->data);
			debug(": base64 result: %d", n->len);
			r = tr069_set_binary_value(value, n);
			free(n);

			break;
		}

		default:
			debug(": = %s\n", dum);
			r = tr069_string2value(elem, dum, 0, value);
		}
	} else {
		switch (elem->type) {
		case T_STR:	/* FIXME: strndup could be avoided by introducing a new tr069_set_lstring_value... */
			if (header->code != AVP_STRING)
				r = DM_INVALID_TYPE;
			else if (!(dum = strndup(header->data, header->len)))
				r = DM_OOM;
			else {
				debug(": = \"%s\"\n", dum);
				r = tr069_set_string_value(value, dum);
			}

			break;

		case T_BINARY:
		case T_BASE64:
			if (header->code != AVP_BINARY)
				r = DM_INVALID_TYPE;
			else {
				debug(": = binary data...\n"); /* FIXME: hex dump for instance... */
				r = tr069_set_binary_data(value, header->len, header->data);
			}

			break;

		case T_SELECTOR:
			if (header->code != AVP_PATH)
				r = DM_INVALID_TYPE;
			else if (!(dum = strndup(header->data, header->len)))
				r = DM_OOM;
			else {
				tr069_selector sel;

				debug(": = \"%s\"\n", dum);

				if (*dum) {
					if (!tr069_name2sel(dum, &sel)) {
						r = DM_INVALID_VALUE;
						break;
					}
				} else
					memset(&sel, 0, sizeof(tr069_selector));

				r = tr069_set_selector_value(value, sel);
			}

			break;

		case T_IPADDR4: {
			int		af;
			struct in_addr	addr;

			if (header->code != AVP_ADDRESS)
				r = DM_INVALID_TYPE;
			else if (!diam_get_address_avp(&af, &addr, header->data) ||
				af != AF_INET)
				r = DM_INVALID_VALUE;
			else {
				debug(": = %s\n", inet_ntoa(addr));

				set_DM_IP4(*value, addr);
			}

			break;
		}

		case T_ENUM: {
			int enumid;

			switch (header->code) {
			case AVP_ENUM:
				if (!(dum = strndup(header->data, header->len)))
					r = DM_OOM;
				else if ((enumid = tr069_enum2int(&elem->u.e,
								  dum)) == -1)
					r = DM_INVALID_VALUE;
				else {
					debug(": = %s (%d)\n", dum, enumid);
					set_DM_ENUM(*value, enumid);
				}

				break;
			case AVP_ENUMID:
				enumid = diam_get_int32_avp(header->data);
				if (enumid < 0 || enumid >= elem->u.e.cnt) {
					r = DM_INVALID_VALUE;
				} else {
					debug(": = %s (%d)\n",
					      tr069_int2enum(&elem->u.e, enumid),
					      enumid);
					set_DM_ENUM(*value, enumid);
				}

				break;
			default:
				r = DM_INVALID_TYPE;
			}

			break;
		}

		case T_INT:
			if (header->code != AVP_INT32)
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT(*value,
					   diam_get_int32_avp(header->data));
				debug(": = %d\n", DM_INT(*value));
			}

			break;

		case T_UINT:
			if (header->code != AVP_UINT32)
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT(*value,
					    diam_get_uint32_avp(header->data));
				debug(": = %u\n", DM_UINT(*value));
			}

			break;

		case T_INT64:
			if (header->code != AVP_INT64)
				r = DM_INVALID_TYPE;
			else {
				set_DM_INT64(*value,
					     diam_get_int64_avp(header->data));
				debug(": = %" PRIi64 "\n", DM_INT64(*value));
			}

			break;

		case T_UINT64:
			if (header->code != AVP_UINT64)
				r = DM_INVALID_TYPE;
			else {
				set_DM_UINT64(*value,
					      diam_get_uint64_avp(header->data));
				debug(": = %" PRIu64 "\n", DM_UINT64(*value));
			}

			break;

		case T_BOOL:
			if (header->code != AVP_BOOL)
				r = DM_INVALID_TYPE;
			else {
				set_DM_BOOL(*value,
					    diam_get_uint8_avp(header->data));
				debug(": = %d\n", DM_BOOL(*value));
			}

			break;

		case T_DATE:
			if (header->code != AVP_DATE)
				r = DM_INVALID_TYPE;
			else {
				set_DM_TIME(*value,
					    diam_get_time_avp(header->data));
				debug(": = (%d) %s", (int)DM_TIME(*value),
				      ctime(DM_TIME_REF(*value)));
			}

			break;

		case T_TICKS:
			switch (header->code) {
			case AVP_ABSTICKS: /* FIXME: has to be converted? */
			case AVP_RELTICKS:
				set_DM_TICKS(*value,
					     diam_get_int64_avp(header->data));
				debug(": = %" PRItick "\n", DM_TICKS(*value));
				break;
			default:
				r = DM_INVALID_TYPE;
			}

			break;

		default:		/* includes T_COUNTER which is non-writable */
			r = DM_INVALID_TYPE;
		}
	}

	free(dum);

	EXIT();
	return r;
}

static DM_RESULT
dmconfig_value2avp(GET_GRP_CONTAINER *container,
		   const struct tr069_element *elem, const DM_VALUE val)
{
	ENTER();

	switch (elem->type) {
	case T_ENUM:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_ENUM;
		case AVP_ENUM:
			if (diam_avpgrp_add_string(container->ctx,
						   &container->grp, AVP_ENUM, 0,
						   VP_TRAVELPING,
						   tr069_int2enum(&elem->u.e,
						   		  DM_ENUM(val)))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s (%d)]\n",
			      tr069_int2enum(&elem->u.e, DM_ENUM(val)),
			      DM_ENUM(val));

			EXIT();
			return DM_OK;
		case AVP_ENUMID:
			if (diam_avpgrp_add_int32(container->ctx, &container->grp,
						  AVP_ENUMID, 0, VP_TRAVELPING,
						  DM_ENUM(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s (%d)]\n",
			      tr069_int2enum(&elem->u.e, DM_ENUM(val)),
			      DM_ENUM(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_COUNTER:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_COUNTER;
		case AVP_COUNTER:
			if (diam_avpgrp_add_uint32(container->ctx, &container->grp,
						   AVP_COUNTER, 0, VP_TRAVELPING,
						   DM_UINT(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %u]\n", DM_UINT(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_INT:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_INT32;
		case AVP_INT32:
			if (diam_avpgrp_add_int32(container->ctx, &container->grp,
						  AVP_INT32, 0, VP_TRAVELPING,
						  DM_INT(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %d]\n", DM_INT(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_UINT:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_UINT32;
		case AVP_UINT32:
			if (diam_avpgrp_add_uint32(container->ctx,
						   &container->grp, AVP_UINT32, 0,
						   VP_TRAVELPING, DM_UINT(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %u]\n", DM_UINT(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_INT64:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_INT64;
		case AVP_INT64:
			if (diam_avpgrp_add_int64(container->ctx, &container->grp,
						  AVP_INT64, 0, VP_TRAVELPING,
						  DM_INT64(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %" PRIi64 "]\n", DM_INT64(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_UINT64:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_UINT64;
		case AVP_UINT64:
			if (diam_avpgrp_add_uint64(container->ctx, &container->grp,
						   AVP_UINT64, 0, VP_TRAVELPING,
						   DM_UINT64(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %" PRIu64 " ]\n", DM_UINT64(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_STR:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_STRING;
		case AVP_STRING:
			if (diam_avpgrp_add_string(container->ctx, &container->grp,
						   AVP_STRING, 0, VP_TRAVELPING,
						   DM_STRING(val) ? : "")) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: \"%s\"]\n", DM_STRING(val) ? : "");

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_BINARY:
	case T_BASE64:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_BINARY;
		case AVP_BINARY:
			if (diam_avpgrp_add_raw(container->ctx, &container->grp,
						AVP_BINARY, 0, VP_TRAVELPING,
						DM_BINARY(val) ? DM_BINARY(val)->data : "",
						DM_BINARY(val) ? DM_BINARY(val)->len : 0)) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: \"binay data....\"]\n"); /* FIXME */

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_IPADDR4:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_ADDRESS;
		case AVP_ADDRESS:
			if (diam_avpgrp_add_address(container->ctx,
						    &container->grp, AVP_ADDRESS,
						    0, VP_TRAVELPING, AF_INET,
						    DM_IP4_REF(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s]\n", inet_ntoa(DM_IP4(val)));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_BOOL:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_BOOL;
		case AVP_BOOL:
			if (diam_avpgrp_add_uint8(container->ctx, &container->grp,
						  AVP_BOOL, 0, VP_TRAVELPING,
						  (uint8_t) DM_BOOL(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %s (%d)]\n",
			      DM_BOOL(val) ? "true" : "false", DM_BOOL(val));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_DATE:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_DATE;
		case AVP_DATE:
			if (diam_avpgrp_add_time(container->ctx, &container->grp,
						 AVP_DATE, 0, VP_TRAVELPING,
						 DM_TIME(val))) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: (%d) %s",
			      (int)DM_TIME(val), ctime(DM_TIME_REF(val)));

			EXIT();
			return DM_OK;
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_SELECTOR:
		switch (container->type) {
		case AVP_UNKNOWN:
			container->type = AVP_PATH;
		case AVP_PATH: {
			char buffer[MAX_PARAM_NAME_LEN];
			char *name;

			if (!DM_SELECTOR(val))
				name = "";
			else if (!(name = tr069_sel2name(*DM_SELECTOR(val),
							 buffer, sizeof(buffer)))) {
				EXIT();
				return DM_INVALID_VALUE;
			}
			if (diam_avpgrp_add_string(container->ctx, &container->grp,
						   AVP_PATH, 0,
						   VP_TRAVELPING, name)) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: \"%s\"]\n", name);

			EXIT();
			return DM_OK;
		}
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	case T_TICKS:
		if (container->type == AVP_UNKNOWN)
			container->type = elem->flags & F_DATETIME ? AVP_ABSTICKS
								   : AVP_RELTICKS;

		switch (container->type) {
		case AVP_ABSTICKS:
		case AVP_RELTICKS: {
			ticks_t t = container->type == AVP_ABSTICKS ? ticks2realtime(DM_TICKS(val))
								    : DM_TICKS(val);

			if (diam_avpgrp_add_int64(container->ctx, &container->grp,
						  container->type, 0, VP_TRAVELPING, t)) {
				EXIT();
				return DM_OOM;
			}

			debug(": [Answer: %" PRItick "]\n", t);

			EXIT();
			return DM_OK;
		}
		default:
			EXIT();
			return DM_INVALID_TYPE;
		}
	default:
		EXIT();
		return DM_INVALID_TYPE;
	}

	/* never reached */

	EXIT();
	return DM_ERROR;
}

static DM_RESULT
dmconfig_set_cb(void *data, const tr069_selector sel,
		const struct tr069_element *elem,
		struct tr069_value_table *base,
		const void *value __attribute__((unused)), DM_VALUE *st)
{
	SET_GRP_CONTAINER	*container = data;

	DM_VALUE		new_value;
	DM_RESULT		r;

	ENTER();

	if ((r = dmconfig_avp2value(container->header, elem, &new_value)) != DM_OK) {
		EXIT();
		return r;
	}

	if (container->session->flags & CMD_FLAG_CONFIGURE) {
		st->flags |= DV_UPDATE_PENDING;
		DM_parity_update(*st);
		cache_add(sel, "", elem, base, st, new_value, 0, NULL);
	} else {
		new_value.flags |= DV_UPDATED;
		DM_parity_update(new_value);
		r = tr069_overwrite_any_value_by_selector(sel, elem->type,
							  new_value,
							  container->session->notify.slot ? : -1);
	}

	EXIT();
	return r;
}

static DM_RESULT
dmconfig_get_cb(void *data, const tr069_selector sb __attribute__((unused)),
		const struct tr069_element *elem, const DM_VALUE val)
{
	return elem ? dmconfig_value2avp(data, elem, val)
		    : DM_VALUE_NOT_FOUND;
}

		/* used by CMD_DB_LIST request */
static int
dmconfig_list_cb(void *data, CB_type type, tr069_id id,
		 const struct tr069_element *elem, const DM_VALUE value)
{
	LIST_CTX		*ctx = data;
	GET_GRP_CONTAINER	get_container = {.type = AVP_UNKNOWN};

	uint32_t		node_type;

	char			*node_name = elem->key;
	char			numbuf[UINT16_DIGITS];

	ENTER();

	if (!node_name) {
		EXIT();
		return 0;
	}

	if (ctx->firstone) {		/* hack that prevents the first element from being processed */
		ctx->firstone = 0;	/* later tr069_walk_by_name might be modified or reimplemented */
		EXIT();
		return 1;
	}

	switch (type) {
	case CB_object_end:
	case CB_table_end:
	case CB_object_instance_end:
		if (ctx->level && ctx->level < ctx->max_level) {
			get_container.grp = ctx->ctx;
			get_container.ctx = talloc_parent(get_container.grp);

			if (diam_avpgrp_add_avpgrp(get_container.ctx, &get_container.grp,
						   AVP_CONTAINER, 0, VP_TRAVELPING, ctx->grp)) {
				EXIT();
				return 0;
			}
			talloc_free(ctx->grp);

			ctx->grp = get_container.ctx;
			ctx->ctx = talloc_parent(ctx->grp);

			if (diam_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER,
					   	   0, VP_TRAVELPING, get_container.grp)) {
				EXIT();
				return 0;
			}
			talloc_free(get_container.grp);
		}
		ctx->level--;

		EXIT();
		return 1;
	case CB_object_start:
		node_type = NODE_TABLE;
		ctx->level++;
		break;
	case CB_object_instance_start:
		snprintf(numbuf, sizeof(numbuf), "%hu", id);
		node_name = numbuf;
	case CB_table_start:
		node_type = NODE_OBJECT;
		ctx->level++;
		break;
	case CB_element:
		node_type = NODE_PARAMETER;
		break;
	default:
		EXIT();
		return 0;
	}

	get_container.ctx = ctx->grp;
	if (!(get_container.grp = new_diam_avpgrp(get_container.ctx))) {
		EXIT();
		return 0;
	}

	if (diam_avpgrp_add_string(get_container.ctx, &get_container.grp,
				   AVP_NODE_NAME, 0, VP_TRAVELPING, node_name)) {
		EXIT();
		return 0;
	}
	if (diam_avpgrp_add_uint32(get_container.ctx, &get_container.grp,
				   AVP_NODE_TYPE, 0, VP_TRAVELPING, node_type)) {
		EXIT();
		return 0;
	}

	switch (node_type) {
	case NODE_PARAMETER:
		if (elem->type == T_POINTER) {
			if (diam_avpgrp_add_uint32(get_container.ctx, &get_container.grp,
						   AVP_NODE_DATATYPE, 0, VP_TRAVELPING,
						   AVP_POINTER)) {
				EXIT();
				return 0;
			}
		} else if (dmconfig_value2avp(&get_container, elem, value)) {
			EXIT();
			return 0;
		}

		if (diam_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER,
					   0, VP_TRAVELPING, get_container.grp)) {
			EXIT();
			return 0;
		}
		talloc_free(get_container.grp);

		break;

	case NODE_TABLE:
	case NODE_OBJECT:
		if (ctx->level < ctx->max_level) {
			ctx->ctx = get_container.grp;
			if (!(ctx->grp = new_diam_avpgrp(ctx->ctx))) {
				EXIT();
				return 0;
			}
		} else {
			if ((node_type == NODE_OBJECT &&
			     diam_avpgrp_add_uint32(get_container.ctx, &get_container.grp,
						    AVP_NODE_SIZE, 0, VP_TRAVELPING,
						    elem->u.t.table->size)) ||
			    diam_avpgrp_add_avpgrp(ctx->ctx, &ctx->grp, AVP_CONTAINER,
					   	   0, VP_TRAVELPING, get_container.grp)) {
				EXIT();
				return 0;
			}
			talloc_free(get_container.grp);
		}
	}

	EXIT();
	return 1;
}

static DM_RESULT
dmconfig_retrieve_enums_cb(void *data,
			   const tr069_selector sb __attribute__((unused)),
			   const struct tr069_element *elem,
			   const DM_VALUE val __attribute__((unused)))
{
	OBJ_GROUP 		*obj = data;

	const struct tr069_enum	*enumer;

	char			*ptr;
	int			i;

	ENTER();

	if (!elem) {
		EXIT();
		return DM_VALUE_NOT_FOUND;
	}

	enumer = &elem->u.e;
	for (ptr = enumer->data, i = enumer->cnt; i; i--, ptr += strlen(ptr) + 1)
		if (diam_avpgrp_add_string(obj->req, &obj->answer_grp,
					   AVP_STRING, 0, VP_TRAVELPING, ptr)) {
			EXIT();
			return DM_OOM;
		}

	EXIT();
	return DM_OK;
}

static inline void
doReboot(void)
{
	ENTER();

	if (getCfgSessionStatus() == CFGSESSION_INACTIVE &&
	    cpe_needs_reboot == pthread_self()) {
		/*tr069_save(); */
		tr069_reboot_actions();
		sleep(REBOOT_DELAY);
		sys_shutdown_system(RB_AUTOBOOT);
	}

	EXIT();
}

