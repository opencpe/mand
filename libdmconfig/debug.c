/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
	functions for debugging purposes (dumping diameter packets and their AVPs)
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "errors.h"
#include "diammsg.h"
#include "codes.h"

#include "debug.h"

struct code2str {
	uint16_t code;
	char *command;
};

#define initC2S(x) { .code = x, .command = #x }

static struct code2str cmd2str[] = {
	initC2S(CMD_DB_SET),
	initC2S(CMD_DB_GET),
	initC2S(CMD_DB_LIST),

	initC2S(CMD_DB_RETRIEVE_ENUMS),
	initC2S(CMD_DB_DUMP),

	initC2S(CMD_DB_ADDINSTANCE),
	initC2S(CMD_DB_DELINSTANCE),

	initC2S(CMD_DB_COMMIT),
	initC2S(CMD_DB_CANCEL),
	initC2S(CMD_DB_SAVE),

	initC2S(CMD_STARTSESSION),
	initC2S(CMD_ENDSESSION),
	initC2S(CMD_SWITCHSESSION),
	initC2S(CMD_SESSIONINFO),

	initC2S(CMD_SUBSCRIBE_NOTIFY),
	initC2S(CMD_UNSUBSCRIBE_NOTIFY),
	initC2S(CMD_PARAM_NOTIFY),
	initC2S(CMD_RECURSIVE_PARAM_NOTIFY),
	initC2S(CMD_GET_PASSIVE_NOTIFICATIONS),
	initC2S(CMD_SUBSCRIBE_GW_NOTIFY),
	initC2S(CMD_UNSUBSCRIBE_GW_NOTIFY),
	initC2S(CMD_GATEWAY_NOTIFY),

	initC2S(CMD_DEV_BOOTSTRAP),
	initC2S(CMD_DEV_WANUP),
	initC2S(CMD_DEV_WANDOWN),
	initC2S(CMD_DEV_SYSUP),
	initC2S(CMD_DEV_GETDEVICE),
	initC2S(CMD_DEV_BOOT),
	initC2S(CMD_DEV_REBOOT),
	initC2S(CMD_DEV_HOTPLUG),
	initC2S(CMD_DEV_DHCP_INFO),
	initC2S(CMD_DEV_DHCP_CIRCUIT),
	initC2S(CMD_DEV_DHCP_REMOTE),
	
	initC2S(CMD_GW_NEW_CLIENT),
	initC2S(CMD_GW_DEL_CLIENT),
	initC2S(CMD_GW_CLIENT_ACCESS),
	initC2S(CMD_GW_GET_CLIENT),
	initC2S(CMD_GW_CLIENT_REQ_ACCESSCLASS),
	initC2S(CMD_GW_CLIENT_SET_ACCESSCLASS),
	initC2S(CMD_GW_HEARTBEAT),
	
	initC2S(CMD_DHCP_CLIENT_ACK),
	initC2S(CMD_DHCP_CLIENT_RELEASE),
	initC2S(CMD_DHCP_CLIENT_EXPIRE),

	initC2S(CMD_CLIENT_ACTIVE_NOTIFY),
	initC2S(CMD_CLIENT_GATEWAY_NOTIFY),
};

static struct code2str avp2str[] = {
	initC2S(AVP_PATH),

	initC2S(AVP_TYPE_PATH),
	initC2S(AVP_INT),
	initC2S(AVP_UINT),
	initC2S(AVP_COUNTER),
	initC2S(AVP_ENUMID),
	initC2S(AVP_ENUM),
	initC2S(AVP_STRING),
	initC2S(AVP_ADDRESS),
	initC2S(AVP_BOOL),
	initC2S(AVP_DATE),
	initC2S(AVP_TIMEVAL),
	initC2S(AVP_RC),
	initC2S(AVP_SESSIONID),
	initC2S(AVP_NOTIFY_TYPE),
	initC2S(AVP_UNKNOWN),
	initC2S(AVP_INT64),
	initC2S(AVP_UINT64),

	initC2S(AVP_HOTPLUGCMD),

	initC2S(AVP_CONTAINER),

	initC2S(AVP_NODE_NAME),
	initC2S(AVP_NODE_TYPE),
	initC2S(AVP_NODE_DATATYPE),
	initC2S(AVP_NODE_SIZE),

	initC2S(AVP_TIMEOUT_SESSION),
	initC2S(AVP_TIMEOUT_REQUEST),

	initC2S(AVP_GW_ZONE),
	initC2S(AVP_GW_CLIENT_ID),
	initC2S(AVP_GW_OBJ_ID),
	initC2S(AVP_GW_IPADDRESS),
	initC2S(AVP_GW_MACADDRESS),
	initC2S(AVP_GW_TOKEN),
	initC2S(AVP_GW_ACCTSESSIONID),
	initC2S(AVP_GW_SESSIONID),
	initC2S(AVP_GW_USERNAME),
	initC2S(AVP_GW_PASSWORD),
	initC2S(AVP_GW_USERAGENT),
	initC2S(AVP_GW_AGENTCIRCUITID),
	initC2S(AVP_GW_AGENTREMOTEID),
	initC2S(AVP_GW_ACCESSCLASS),

	initC2S(AVP_DHCP_IPADDRESS),
	initC2S(AVP_DHCP_MACADDRESS),
	initC2S(AVP_DHCP_CLIENT_ID),
	initC2S(AVP_DHCP_REMOTE_ID),
	initC2S(AVP_DHCP_CIRCUIT_ID),
	initC2S(AVP_DHCP_HOSTNAME),
	initC2S(AVP_DHCP_EXPIRE),
	initC2S(AVP_DHCP_REMAINING),
	initC2S(AVP_DHCP_INTERFACE),
	initC2S(AVP_DHCP_SUBSCRIBER_ID),
};

static int comp_code(const void *m1, const void *m2)
{
	struct code2str *a = (struct code2str *) m1;
	struct code2str *b = (struct code2str *) m2;

	if (a->code > b->code)
		return 1;
	else if (a->code < b->code)
		return -1;
	else 
		return 0;
}

static const char *unk_code = "unknown code";
static const char *unk_avp = "unknown code";

const char *_get_cmd(uint16_t code)
{
	struct code2str srch = { .code = code };
	struct code2str *res;

	res = bsearch(&srch, &cmd2str, sizeof(cmd2str) / sizeof(struct code2str),
		      sizeof(struct code2str), comp_code);
	if (res)
		return res->command;

	return unk_code;
}
const char *_get_avp(uint16_t code)
{
	struct code2str srch = { .code = code };
	struct code2str *res;

	res = bsearch(&srch, &avp2str, sizeof(avp2str) / sizeof(struct code2str),
		      sizeof(struct code2str), comp_code);
	if (res)
		return res->command;

	return unk_avp;
}

static void init_code2str(void) __attribute__ ((constructor));

void init_code2str(void)
{
	qsort(&cmd2str, sizeof(cmd2str) / sizeof(struct code2str), sizeof(struct code2str), comp_code);
	qsort(&avp2str, sizeof(avp2str) / sizeof(struct code2str), sizeof(struct code2str), comp_code);
}

static void hexdump(void *data, int len);

static void
hexdump(void *data, int len) {
	for(int i = 0; i < len; i++, data++) {
		if((i % 16) == 0)
			fprintf(stderr, "\n%08x: ", i);

		fprintf(stderr, "%02x ", *(uint8_t *)data);
	}
	fprintf(stderr, "\n");
}

static const char *indent(int level)
{
	static const char space[] = "                ";

	if (level * 2 < strlen(space))
		return space + strlen(space) - level * 2;

	return space;
}

static void dump_avpgrp(int level, DIAM_AVPGRP *avpgrp)
{
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;

	while(!diam_avpgrp_get_avp(avpgrp, &code, &flags, &vendor_id, &data, &len)) {
		fprintf(stderr, "%sC: %8d %-20s, F: %02x, V: %8d, L: %6d, %p\n", indent(level), code, _get_avp(code), flags, vendor_id, len, data);
		if (code == AVP_CONTAINER) {
			DIAM_AVPGRP *avpgrp1 = diam_decode_avpgrp(NULL, data, len);

			dump_avpgrp(level + 1, avpgrp1);
			talloc_free(avpgrp1);
		}
	}
	fprintf(stderr, "\n");
}

void
dump_diam_packet(DIAM_REQUEST *req) {
	uint32_t	code;
	uint8_t		flags;
	uint32_t	vendor_id;
	void		*data;
	size_t		len;
	DIAM_PACKET	*packet = &req->packet;

	hexdump(packet, diam_packet_length(packet));

	fprintf(stderr, "Version: %d\n", packet->version);
	fprintf(stderr, " Length: %d\n", diam_packet_length(packet));
	fprintf(stderr, "  Flags: %02x\n", packet->flags);
	fprintf(stderr, "Command: %s (%d)\n", _get_cmd(diam_packet_code(packet)), diam_packet_code(packet));
	fprintf(stderr, " App-Id: %08x\n", ntohl(packet->app_id));
	fprintf(stderr, " Hop-Id: %08x\n", ntohl(packet->hop2hop_id));
	fprintf(stderr, " End-Id: %08x\n", ntohl(packet->end2end_id));

	diam_request_reset_avp(req);
	while(!diam_request_get_avp(req, &code, &flags, &vendor_id, &data, &len)) {
		fprintf(stderr, "C:   %8d %-20s, F: %02x, V: %8d, L: %6d, %p\n", code, _get_avp(code), flags, vendor_id, len, data);
		if(code == AVP_CONTAINER) {
			DIAM_AVPGRP *avpgrp = diam_decode_avpgrp(req, data, len);

			dump_avpgrp(1, avpgrp);
			talloc_free(avpgrp);
		}
	}
}

