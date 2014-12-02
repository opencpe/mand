/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
	functions for debugging purposes (dumping dmconfig packets and their AVPs)
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

#include <ralloc.h>

#include "errors.h"
#include "dmmsg.h"
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

	initC2S(CMD_CLIENT_ACTIVE_NOTIFY),
};

static struct code2str avp2str[] = {
	initC2S(AVP_NAME),
	initC2S(AVP_TYPE),

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
	initC2S(AVP_TABLE),
	initC2S(AVP_INSTANCE),
	initC2S(AVP_OBJECT),
	initC2S(AVP_ELEMENT),

	initC2S(AVP_TIMEOUT_SESSION),
	initC2S(AVP_TIMEOUT_REQUEST),
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

void
hexdump(void *data, int len) {
	for(int i = 0; i < len; i++, data++) {
		if((i % 16) == 0)
			fprintf(stderr, "\n%08x: ", i);

		fprintf(stderr, "%02x ", *(uint8_t *)data);
	}
	fprintf(stderr, "\n");
}

static const char *indent(unsigned int level)
{
	static const char space[] = "                ";

	if (level * 2 < strlen(space))
		return space + strlen(space) - level * 2;

	return space;
}

static void dump_avpgrp(unsigned int level, DM2_AVPGRP *grp)
{
	uint32_t code;
	uint32_t vendor_id;
	void *data;
	size_t size;
	DM2_AVPGRP obj;

	while(dm_expect_avp(grp, &code, &vendor_id, &data, &size) == RC_OK) {
		fprintf(stderr, "%sC: %8d %-20s, V: %8d, L: %6zd, %p\n", indent(level), code, _get_avp(code), vendor_id, size, data);

		switch (code) {
		case AVP_CONTAINER:
		case AVP_TABLE:
		case AVP_INSTANCE:
		case AVP_OBJECT:
		case AVP_ELEMENT:
			dm_init_avpgrp(grp->ctx, data, size, &obj);
			dump_avpgrp(level + 1, &obj);
			break;

		default:
			break;
		}
	}
}

void
dump_dm_packet(DM_PACKET *packet)
{
	DM2_AVPGRP grp;

	hexdump(packet, dm_packet_length(packet));

	fprintf(stderr, "Version: %d\n", packet->version);
	fprintf(stderr, " Length: %d\n", dm_packet_length(packet));
	fprintf(stderr, "  Flags: %02x\n", packet->flags);
	fprintf(stderr, "Command: %s (%d)\n", _get_cmd(dm_packet_code(packet)), dm_packet_code(packet));
	fprintf(stderr, " App-Id: %08x\n", ntohl(packet->app_id));
	fprintf(stderr, " Hop-Id: %08x\n", ntohl(packet->hop2hop_id));
	fprintf(stderr, " End-Id: %08x\n", ntohl(packet->end2end_id));

	dm_init_packet(packet, &grp);
	dump_avpgrp(0, &grp);
}

