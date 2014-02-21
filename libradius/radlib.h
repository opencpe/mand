/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libradius/radlib.h,v 1.7 2004/04/27 15:00:29 ru Exp $
 */

#ifndef _RADLIB_H_
#define _RADLIB_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include "radlib_compat.h"

/* Limits */
#define RAD_MAX_ATTR_LEN		253

/* Setup types */
#define RADIUS_AUTH		0   /* RADIUS authentication, default */
#define RADIUS_ACCT		1   /* RADIUS accounting */

/* Message types */
#define RAD_ACCESS_REQUEST		1
#define RAD_ACCESS_ACCEPT		2
#define RAD_ACCESS_REJECT		3
#define RAD_ACCOUNTING_REQUEST		4
#define RAD_ACCOUNTING_RESPONSE		5
#define RAD_ACCESS_CHALLENGE		11

/* Attribute types and values */
#define RAD_USER_NAME			1	/* String */
#define RAD_USER_PASSWORD		2	/* String */
#define RAD_CHAP_PASSWORD		3	/* String */
#define RAD_NAS_IP_ADDRESS		4	/* IP address */
#define RAD_NAS_PORT			5	/* Integer */
#define RAD_SERVICE_TYPE		6	/* Integer */
	#define RAD_LOGIN			1
	#define RAD_FRAMED			2
	#define RAD_CALLBACK_LOGIN		3
	#define RAD_CALLBACK_FRAMED		4
	#define RAD_OUTBOUND			5
	#define RAD_ADMINISTRATIVE		6
	#define RAD_NAS_PROMPT			7
	#define RAD_AUTHENTICATE_ONLY		8
	#define RAD_CALLBACK_NAS_PROMPT		9
	#define RAD_AUTHORIZE_ONLY		17
#define RAD_FRAMED_PROTOCOL		7	/* Integer */
	#define RAD_PPP				1
	#define RAD_SLIP			2
	#define RAD_ARAP			3	/* Appletalk */
	#define RAD_GANDALF			4
	#define RAD_XYLOGICS			5
#define RAD_FRAMED_IP_ADDRESS		8	/* IP address */
#define RAD_FRAMED_IP_NETMASK		9	/* IP address */
#define RAD_FRAMED_ROUTING		10	/* Integer */
#define RAD_FILTER_ID			11	/* String */
#define RAD_FRAMED_MTU			12	/* Integer */
#define RAD_FRAMED_COMPRESSION		13	/* Integer */
	#define RAD_COMP_NONE			0
	#define RAD_COMP_VJ			1
	#define RAD_COMP_IPXHDR			2
#define RAD_LOGIN_IP_HOST		14	/* IP address */
#define RAD_LOGIN_SERVICE		15	/* Integer */
#define RAD_LOGIN_TCP_PORT		16	/* Integer */
     /* unassiged			17 */
#define RAD_REPLY_MESSAGE		18	/* String */
#define RAD_CALLBACK_NUMBER		19	/* String */
#define RAD_CALLBACK_ID			20	/* String */
     /* unassiged			21 */
#define RAD_FRAMED_ROUTE		22	/* String */
#define RAD_FRAMED_IPX_NETWORK		23	/* IP address */
#define RAD_STATE			24	/* String */
#define RAD_CLASS			25	/* String */
#define RAD_VENDOR_SPECIFIC		26	/* Integer */
#define RAD_SESSION_TIMEOUT		27	/* Integer */
#define RAD_IDLE_TIMEOUT		28	/* Integer */
#define RAD_TERMINATION_ACTION		29	/* Integer */
#define RAD_CALLED_STATION_ID		30	/* String */
#define RAD_CALLING_STATION_ID		31	/* String */
#define RAD_NAS_IDENTIFIER		32	/* Integer */
#define RAD_PROXY_STATE			33	/* Integer */
#define RAD_LOGIN_LAT_SERVICE		34	/* Integer */
#define RAD_LOGIN_LAT_NODE		35	/* Integer */
#define RAD_LOGIN_LAT_GROUP		36	/* Integer */
#define RAD_FRAMED_APPLETALK_LINK	37	/* Integer */
#define RAD_FRAMED_APPLETALK_NETWORK	38	/* Integer */
#define RAD_FRAMED_APPLETALK_ZONE	39	/* Integer */
     /* reserved for accounting		40-59 */

#define RAD_CHAP_CHALLENGE		60	/* String */
#define RAD_NAS_PORT_TYPE		61	/* Integer */
	#define RAD_ASYNC			0
	#define RAD_SYNC			1
	#define RAD_ISDN_SYNC			2
	#define RAD_ISDN_ASYNC_V120		3
	#define RAD_ISDN_ASYNC_V110		4
	#define RAD_VIRTUAL			5
	#define RAD_PIAFS			6
	#define RAD_HDLC_CLEAR_CHANNEL		7
	#define RAD_X_25			8
	#define RAD_X_75			9
	#define RAD_G_3_FAX			10
	#define RAD_SDSL			11
	#define RAD_ADSL_CAP			12
	#define RAD_ADSL_DMT			13
	#define RAD_IDSL			14
	#define RAD_ETHERNET			15
	#define RAD_XDSL			16
	#define RAD_CABLE			17
	#define RAD_WIRELESS_OTHER		18
	#define RAD_WIRELESS_IEEE_802_11	19
#define RAD_PORT_LIMIT			62	/* Integer */
#define RAD_LOGIN_LAT_PORT		63	/* Integer */
#define RAD_ARAP_PASSWORD		70	/* Octets */
#define RAD_ARAP_FEATURES		71	/* Octets */
#define RAD_ARAP_ZONE_ACCESS		72	/* Integer */
        #define RAD_ARAP_ZONE_DEFAULT		1
        #define RAD_ARAP_ZONE_FILTER_INCLUSIVE	2
        #define RAD_ARAP_ZONE_FILTER_EXCLUSIVE	4
#define RAD_ARAP_SECURITY		73	/* Integer */
#define RAD_ARAP_SECURITY_DATA		74	/* String */
#define	RAD_PASSWORD_RETRY		75	/* Integer */
#define	RAD_PROMPT			76	/* Integer */
        #define RAD_PROMPT_NO_ECHO		0
        #define RAD_PROMPT_ECHO			1
#define RAD_CONNECT_INFO		77	/* String */
#define RAD_EAP_MESSAGE			79	/* Octets */
#define RAD_MESSAGE_AUTHENTIC		80	/* Octets */
#define RAD_ACCT_INTERIM_INTERVAL	85	/* Integer */
#define RAD_NAS_PORT_ID			87	/* String */
#define RAD_FRAMED_POOL			88	/* String */
#define RAD_CHARGEABLE_USER_IDENTITY	89	/* String */
#define RAD_NAS_IPV6_ADDRESS		95	/* IPv6 address */
#define RAD_FRAMED_INTERFACE_ID		96	/* 8 octets */
#define RAD_FRAMED_IPV6_PREFIX		97	/* Octets */
#define RAD_LOGIN_IPV6_HOST		98	/* IPv6 address */
#define RAD_FRAMED_IPV6_ROUTE		99	/* String */
#define RAD_FRAMED_IPV6_POOL		100	/* String */

/* Accounting attribute types and values */
#define RAD_ACCT_STATUS_TYPE		40	/* Integer */
	#define RAD_START			1
	#define RAD_STOP			2
	#define RAD_UPDATE			3
	#define RAD_ACCOUNTING_ON		7
	#define RAD_ACCOUNTING_OFF		8
#define RAD_ACCT_DELAY_TIME		41	/* Integer */
#define RAD_ACCT_INPUT_OCTETS		42	/* Integer */
#define RAD_ACCT_OUTPUT_OCTETS		43	/* Integer */
#define RAD_ACCT_SESSION_ID		44	/* String */
#define RAD_ACCT_AUTHENTIC		45	/* Integer */
	#define RAD_AUTH_RADIUS			1
	#define RAD_AUTH_LOCAL			2
	#define RAD_AUTH_REMOTE			3
#define RAD_ACCT_SESSION_TIME		46	/* Integer */
#define RAD_ACCT_INPUT_PACKETS		47	/* Integer */
#define RAD_ACCT_OUTPUT_PACKETS		48	/* Integer */
#define RAD_ACCT_TERMINATE_CAUSE	49	/* Integer */
        #define RAD_TERM_USER_REQUEST		1
        #define RAD_TERM_LOST_CARRIER		2
        #define RAD_TERM_LOST_SERVICE		3
        #define RAD_TERM_IDLE_TIMEOUT		4
        #define RAD_TERM_SESSION_TIMEOUT	5
        #define RAD_TERM_ADMIN_RESET		6
        #define RAD_TERM_ADMIN_REBOOT		7
        #define RAD_TERM_PORT_ERROR		8
        #define RAD_TERM_NAS_ERROR		9
        #define RAD_TERM_NAS_REQUEST		10
        #define RAD_TERM_NAS_REBOOT		11
        #define RAD_TERM_PORT_UNNEEDED		12
        #define RAD_TERM_PORT_PREEMPTED		13
        #define RAD_TERM_PORT_SUSPENDED		14
        #define RAD_TERM_SERVICE_UNAVAILABLE    15
        #define RAD_TERM_CALLBACK		16
        #define RAD_TERM_USER_ERROR		17
        #define RAD_TERM_HOST_REQUEST		18
#define	RAD_ACCT_MULTI_SESSION_ID	50	/* String */
#define	RAD_ACCT_LINK_COUNT		51	/* Integer */
#define RAD_ACCT_INPUT_GIGAWORDS	52	/* Integer */
#define RAD_ACCT_OUTPUT_GIGAWORDS	53	/* Integer */
#define RAD_EVENT_TIMESTAMP		55	/* Integer */

struct rad_handle;
struct rad_packet;
struct rad_setup;
struct rad_queue;

struct rad_stats {
	int		 requests;
	int		 retransmissions;
	int		 responses;
	int		 access_accepts;
	int		 access_rejects;
	int		 access_challenges;
	int		 malformed_responses;
	int		 bad_authenticators;
	int		 pending_requests;
	int		 timeouts;
	int		 unknown_types;
	int		 packets_dropped;
};

struct rad_server {
	int		 type;          /* Server type AUTH / ACCT */
	struct sockaddr_in addr;	/* Address of server */
	char		*secret;	/* Shared secret */
	int		 timeout;	/* Timeout in seconds */
	int		 max_tries;	/* Number of tries before giving up */

	LIST_HEAD(rad_queue_list, rad_queue) queues; /* request queues (first element is the current one) */

	struct rad_stats stats;
};

extern unsigned int rad_auth_invalid_server_addresses;
extern unsigned int rad_acct_invalid_server_addresses;

struct timeval;

typedef void (rad_notify_cb)(int, struct rad_handle *, void *, void *);

__BEGIN_DECLS
void                     rad_init(void);
struct rad_handle	*rad_acct_open(void *);
struct rad_handle	*rad_auth_open(void *);
void                     rad_notify(int, struct rad_handle *);
void			 rad_close(struct rad_handle *);
struct rad_packet	*rad_init_request(struct rad_handle *, int);
struct in_addr		 rad_cvt_addr(const void *);
u_int32_t		 rad_cvt_int(const void *);
u_int64_t		 rad_cvt_int64(const void *);
char			*rad_cvt_string(const void *, size_t);
int			 rad_get_code(struct rad_packet *);
void			 rad_get_reset(struct rad_packet *);
int			 rad_get_attr(struct rad_packet *, const void **,
			    size_t *);
int			 rad_put_addr(struct rad_packet *, int, struct in_addr);
int			 rad_put_attr(struct rad_packet *, int,
			    const void *, size_t);
int			 rad_put_int(struct rad_packet *, int, u_int32_t);
int			 rad_put_int64(struct rad_packet *, int, u_int64_t);
int			 rad_put_string(struct rad_packet *, int,
			    const char *);
int			 rad_put_message_authentic(struct rad_packet *);
ssize_t			 rad_request_authenticator(struct rad_packet *, char *,
			    size_t);
int			 rad_send_request(struct rad_setup *, struct rad_handle *);
const char		*rad_server_secret(struct rad_handle *);
const char		*rad_strerror(struct rad_handle *);
u_char			*rad_demangle(struct rad_handle *, const void *,
			    size_t);

struct rad_setup	*rad_setup_open(int, rad_notify_cb *, void *);
struct rad_server 	*rad_new_server(int, const struct in_addr, int, const char *, int, int);
int			 rad_update_server(struct rad_server *,
					   int, const struct in_addr, int, const char *, int, int);
void			 rad_free_server(struct rad_server *);
int			 rad_add_server(struct rad_setup *, uint32_t, struct rad_server *);
int			 rad_remove_server(struct rad_setup *, uint32_t);


struct rad_packet	*rad_request(struct rad_handle *);
struct rad_packet	*rad_response(struct rad_handle *);

struct rad_packet	*rad_new_request(const unsigned char *, ssize_t);
struct rad_packet	*rad_init_response(const struct rad_packet *, int);
void			 rad_free_packet(const struct rad_packet *);

int			 is_valid_request(struct rad_packet *, const char *);

int			 rad_send_answer(int, struct rad_packet *, const char *,
					 int, const struct sockaddr *, socklen_t);
int			 rad_send_answer_from(int, struct rad_packet *, const char *,
					      int, const struct sockaddr *, socklen_t,
					      const struct in_addr);

__END_DECLS

#endif /* _RADLIB_H_ */
