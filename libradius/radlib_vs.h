/*-
 * Copyright (c) 2002 Brian Somers <brian@Awfulhak.org>
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
 * $FreeBSD: src/lib/libradius/radlib_vs.h,v 1.3 2004/04/27 15:00:29 ru Exp $
 */

#ifndef _RADLIB_VS_H_
#define _RADLIB_VS_H_

#include <sys/types.h>
#include <netinet/in.h>
#include "radlib_compat.h"

#define	RAD_VENDOR_MICROSOFT	311		/* rfc2548 */
	#define	RAD_MICROSOFT_MS_CHAP_RESPONSE			1
	#define	RAD_MICROSOFT_MS_CHAP_ERROR			2
	#define	RAD_MICROSOFT_MS_CHAP_PW_1			3
	#define	RAD_MICROSOFT_MS_CHAP_PW_2			4
	#define	RAD_MICROSOFT_MS_CHAP_LM_ENC_PW			5
	#define	RAD_MICROSOFT_MS_CHAP_NT_ENC_PW			6
	#define	RAD_MICROSOFT_MS_MPPE_ENCRYPTION_POLICY		7
	#define	RAD_MICROSOFT_MS_MPPE_ENCRYPTION_TYPES		8
	#define	RAD_MICROSOFT_MS_RAS_VENDOR			9
	#define	RAD_MICROSOFT_MS_CHAP_DOMAIN			10
	#define	RAD_MICROSOFT_MS_CHAP_CHALLENGE			11
	#define	RAD_MICROSOFT_MS_CHAP_MPPE_KEYS			12
	#define	RAD_MICROSOFT_MS_BAP_USAGE			13
	#define	RAD_MICROSOFT_MS_LINK_UTILIZATION_THRESHOLD	14
	#define	RAD_MICROSOFT_MS_LINK_DROP_TIME_LIMIT		15
	#define	RAD_MICROSOFT_MS_MPPE_SEND_KEY			16
	#define	RAD_MICROSOFT_MS_MPPE_RECV_KEY			17
	#define	RAD_MICROSOFT_MS_RAS_VERSION			18
	#define	RAD_MICROSOFT_MS_OLD_ARAP_PASSWORD		19
	#define	RAD_MICROSOFT_MS_NEW_ARAP_PASSWORD		20
	#define	RAD_MICROSOFT_MS_ARAP_PASSWORD_CHANGE_REASON	21
	#define	RAD_MICROSOFT_MS_FILTER				22
	#define	RAD_MICROSOFT_MS_ACCT_AUTH_TYPE			23
	#define	RAD_MICROSOFT_MS_ACCT_EAP_TYPE			24
	#define	RAD_MICROSOFT_MS_CHAP2_RESPONSE			25
	#define	RAD_MICROSOFT_MS_CHAP2_SUCCESS			26
	#define	RAD_MICROSOFT_MS_CHAP2_PW			27
	#define	RAD_MICROSOFT_MS_PRIMARY_DNS_SERVER		28
	#define	RAD_MICROSOFT_MS_SECONDARY_DNS_SERVER		29
	#define	RAD_MICROSOFT_MS_PRIMARY_NBNS_SERVER		30
	#define	RAD_MICROSOFT_MS_SECONDARY_NBNS_SERVER		31
	#define	RAD_MICROSOFT_MS_ARAP_CHALLENGE			33

#define SALT_LEN    2

#define	RAD_VENDOR_DSLF		3561
        #define	RAD_DSLF_AGENT_CIRCUIT_ID			1
        #define	RAD_DSLF_AGENT_REMOTE_ID			2
        #define	RAD_DSLF_ACTUAL_DATA_RATE_UPSTREAM		129
        #define	RAD_DSLF_ACTUAL_DATA_RATE_DOWNSTREAM		130
        #define	RAD_DSLF_MINIMUM_DATA_RATE_UPSTREAM		131
        #define	RAD_DSLF_MINIMUM_DATA_RATE_DOWNSTREAM		132
        #define	RAD_DSLF_ATTAINABLE_DATA_RATE_UPSTREAM		133
        #define	RAD_DSLF_ATTAINABLE_DATA_RATE_DOWNSTREAM	134
        #define	RAD_DSLF_MAXIMUM_DATA_RATE_UPSTREAM		135
        #define	RAD_DSLF_MAXIMUM_DATA_RATE_DOWNSTREAM		136
        #define	RAD_DSLF_MINIMUM_DATA_RATE_UPSTREAM_LOW_POWER	137
        #define	RAD_DSLF_MINIMUM_DATA_RATE_DOWNSTREAM_LOW_POWER	138
        #define	RAD_DSLF_MAXIMUM_INTERLEAVING_DELAY_UPSTREAM	139
        #define	RAD_DSLF_ACTUAL_INTERLEAVING_DELAY_UPSTREAM	140
        #define	RAD_DSLF_MAXIMUM_INTERLEAVING_DELAY_DOWNSTREAM	141
        #define	RAD_DSLF_ACTUAL_INTERLEAVING_DELAY_DOWNSTREAM	142
        #define	RAD_DSLF_ACCESS_LOOP_ENCAPSULATION		144
        #define	RAD_DSLF_IWF_SESSION				254

#define	RAD_VENDOR_TRAVELPING	18681
        #define	RAD_TRAVELPING_GW_VERSION			1
        #define	RAD_TRAVELPING_FW_VARIANT			2
        #define	RAD_TRAVELPING_FW_VERSION			3
        #define	RAD_TRAVELPING_GW_CONFIG			4
        #define	RAD_TRAVELPING_ENC_IV				5
        #define	RAD_TRAVELPING_PASSWORD				6
        #define	RAD_TRAVELPING_USERAGENT			7
        #define	RAD_TRAVELPING_AUTH_REPLY_CODE			8
        #define	RAD_TRAVELPING_ACCESS_CLASS_ID			9
        #define	RAD_TRAVELPING_HOSTNAME				10		/* DHCP Option 12: Host Name */
        #define	RAD_TRAVELPING_DHCP_REQUEST_OPTION_LIST		11		/* List of DHCP Options in the first DHCP request */
        #define	RAD_TRAVELPING_DHCP_PARAMETER_REQUEST_LIST	12		/* DHCP Option 55: Parameter Request List */
        #define	RAD_TRAVELPING_DHCP_VENDOR_CLASS_ID		13		/* DHCP Option 60: Vendor class identifier */
        #define	RAD_TRAVELPING_DHCP_CLIENT_ID			14		/* DHCP Option 61: Client identifier */
        #define	RAD_TRAVELPING_LOCATION_ID			15
        #define	RAD_TRAVELPING_NAT_IP_ADDRESS			16
        #define	RAD_TRAVELPING_ZONE_ID				17
        #define	RAD_TRAVELPING_MONITOR_ID			18		/* actually a monitoring target Id */
        #define	RAD_TRAVELPING_RELATED_SESSION_ID		19
        #define	RAD_TRAVELPING_MONITOR_SESSION_ID		20		/* arbitrary monitoring session Id */
        #define	RAD_TRAVELPING_MAX_INPUT_OCTETS			21
        #define	RAD_TRAVELPING_MAX_OUTPUT_OCTETS		22
        #define	RAD_TRAVELPING_MAX_TOTAL_OCTETS			23
        #define	RAD_TRAVELPING_EXIT_ACCESS_CLASS_ID		24
        #define	RAD_TRAVELPING_ACCESS_RULE			25
        #define	RAD_TRAVELPING_ACCESS_GROUP_ID			26
        #define	RAD_TRAVELPING_NAT_POOL_ID			27
        #define	RAD_TRAVELPING_NAT_PORT_START			28
        #define	RAD_TRAVELPING_NAT_PORT_END			29
        #define	RAD_TRAVELPING_KEEP_ALIVE_TIMEOUT		30


#define	RAD_VENDOR_WISPR	14122
        #define	RAD_WISPR_LOCATION_ID				1
        #define	RAD_WISPR_LOCATION_NAME				2
        #define	RAD_WISPR_LOGOFF_URL				3
        #define	RAD_WISPR_REDIRECTION_URL			4
        #define	RAD_WISPR_BANDWIDTH_MIN_UP			5
        #define	RAD_WISPR_BANDWIDTH_MIN_DOWN			6
        #define	RAD_WISPR_BANDWIDTH_MAX_UP			7
        #define	RAD_WISPR_BANDWIDTH_MAX_DOWN			8
        #define	RAD_WISPR_SESSION_TERMINATE_TIME		9
        #define	RAD_WISPR_SESSION_TERMINATE_END_OF_DAY		10
        #define	RAD_WISPR_BILLING_CLASS_OF_SERVICE		11

struct rad_handle;

__BEGIN_DECLS
int	 rad_get_vendor_attr(u_int32_t *, const void **, size_t *);
int	 rad_put_vendor_addr(struct rad_packet *, int, int, struct in_addr);
int	 rad_put_vendor_attr(struct rad_packet *, int, int, const void *,
	    size_t);
int	 rad_put_vendor_int(struct rad_packet *, int, int, u_int32_t);
int	 rad_put_vendor_string(struct rad_packet *, int, int, const char *);
u_char	*rad_demangle_mppe_key(struct rad_handle *, const void *, size_t,
	    size_t *);
__END_DECLS

#endif /* _RADLIB_VS_H_ */
