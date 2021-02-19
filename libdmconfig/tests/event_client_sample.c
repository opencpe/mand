/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * libdmconfig client lib sample: uses the nonblocking libev-based API
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <assert.h>

#include <ev.h>
#include <talloc.h>

#include <libdmconfig/dmconfig.h>
#include <libdmconfig/dm_dmconfig_rpc_stub.h>

#define CB_ERR(...) do {		\
	fprintf(stderr, __VA_ARGS__);	\
	return;				\
} while (0)

/* registers END SESSION when it is called the 7. time */
static void
registerEndSession(DMCONTEXT *dmCtx)
{
	static int counter = 0;

	if (++counter == 7) {
		if (rpc_endsession_async(dmCtx))
			CB_ERR("Couldn't register END SESSION request.\n");
		printf("END SESSION registered.\n");
	}
}

static void
listReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't list object.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't list object.\n");

	printf("Object listed.\n"
	       "Retrieved nodes:\n");

	uint32_t code, vendor_id;
	void *data;
	size_t size;

	while (dm_expect_avp(answer_grp, &code, &vendor_id, &data, &size) == RC_OK) {
		assert(vendor_id == VP_TRAVELPING);

		DM2_AVPGRP container;
		dm_init_avpgrp(answer_grp->ctx, data, size, &container);

		char *name;
		uint32_t type;

		switch (code) { /* type */
		case AVP_OBJECT:
		case AVP_TABLE:
			rc = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name);
			if (rc != RC_OK)
				CB_ERR("Couldn't decode AVP_OBJECT.\n");
			printf("Object: %s\n", name);
			talloc_free(name);
			break;
		case AVP_ELEMENT:
			rc = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name);
			if (rc != RC_OK)
				CB_ERR("Couldn't decode AVP_ELEMENT.\n");
			rc = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type);
			if (rc != RC_OK)
				CB_ERR("Couldn't decode AVP_ELEMENT.\n");
			printf("Parameter(type:%" PRIu32 "): %s\n", type, name);
			talloc_free(name);
			break;
		default:
			CB_ERR("Invalid element type retrieved.\n");
		}
	}

	registerEndSession(dmCtx);
}

static void
dumpReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't dump database.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't dump database.\n");

	printf("Data base dumped.\n");

	char *data;
	rc = dm_expect_string_type(answer_grp, AVP_STRING, VP_TRAVELPING, &data);
	if (rc != RC_OK)
		CB_ERR("Allocation error.\n");

	printf("Received data:\n%s", data);
	talloc_free(data);

	registerEndSession(dmCtx);
}

static void
instanceDeleted(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't delete instance.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't delete instance.\n");

	printf("Instance deleted.\n");

	registerEndSession(dmCtx);
}

static void
instanceAdded(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't add instance.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't add instance.\n");

	printf("Instance added.\n");

	uint16_t instance;
	rc = dm_expect_uint16_type(answer_grp, AVP_UINT16, VP_TRAVELPING, &instance);
	if (rc != RC_OK)
		CB_ERR("Cannot decode instance id.\n");

	char *charval;
	if (asprintf(&charval, "dhcp.client.interfaces.%u", instance) == -1)
		CB_ERR("Allocation error.\n");
	printf("New instance: %s\n", charval);

	rc = rpc_db_delinstance_async(dmCtx, charval, instanceDeleted, NULL);
	free(charval);
	if (rc != RC_OK)
		CB_ERR("Couldn't register DELETE INSTANCE request.\n");
	printf("DELETE INSTANCE request registered.\n");

	registerEndSession(dmCtx);
}

static void
parametersReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't get parameters.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't get parameters.\n");

	printf("Retrieved parameters:\n");

	uint32_t intval;
	char *charval, *address;

	uint32_t code, vendor_id;
	void *data;
	size_t len;

	if (dm_expect_uint32_type(answer_grp, AVP_UINT32, VP_TRAVELPING, &intval) != RC_OK ||
	    dm_expect_string_type(answer_grp, AVP_STRING, VP_TRAVELPING, &charval) != RC_OK ||
	    dm_expect_avp(answer_grp, &code, &vendor_id, &data, &len) != RC_OK ||
	    dm_decode_unknown_as_string(code, data, len, &address) != RC_OK ||
	    dm_expect_avp(answer_grp, &code, &vendor_id, &data, &len) != RC_OK)
		CB_ERR("Couldn't decode GET response.\n");

	printf("Received integer: %" PRIu32 "\n"
	       "Received string: \"%s\"\n"
	       "Received address: %s\n"
	       "Received unknown data: %lu, %p\n",
	       intval, charval, address, len, data);

	free(address);

	registerEndSession(dmCtx);
}

static void
committedChanges(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't commit changes.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't commit changes.\n");

	printf("Changes committed.\n");

	registerEndSession(dmCtx);
}

static void
parametersSet(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't set parameters.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't set parameters.\n");

	printf("Parameters set.\n");

	rc = rpc_db_commit_async(dmCtx, committedChanges, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register COMMIT request.\n");
	printf("COMMIT request registered.\n");

	registerEndSession(dmCtx);
}

static void
sessionStarted(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't start session.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't start session.\n");

	printf("Session started. Session Id: %" PRIu32 "\n", dmCtx->sessionid);

	struct rpc_db_set_path_value set_values[] = {
		{
			.path = "system.dns-resolver.options.timeout",
			.value.code = AVP_UNKNOWN,
			.value.vendor_id = VP_TRAVELPING,
			.value.data = "42",
			.value.size = 2
		},
		{
			.path = "system.location",
			.value.code = AVP_STRING,
			.value.vendor_id = VP_TRAVELPING,
			.value.data = "TEST",
			.value.size = 4
		}
	};

	rc = rpc_db_set_async(dmCtx, sizeof(set_values)/sizeof(set_values[0]), set_values, parametersSet, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register SET request.\n");
	printf("SET request registered.\n");

	static const char *get_values[] = {
		"dhcp.server.lease-time",
		"system-state.platform.machine",
		"interfaces.interface.1.ipv4.address.1.ip",
		"system-state.platform.serial-number"
	};

	rc = rpc_db_get_async(dmCtx, sizeof(get_values)/sizeof(get_values[0]), get_values, parametersReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register GET request.\n");
	printf("GET request registered.\n");

	rc = rpc_db_addinstance_async(dmCtx, "dhcp.client.interfaces",
	                              DM_ADD_INSTANCE_AUTO, instanceAdded, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register ADD INSTANCE request.\n");
	printf("ADD INSTANCE request registered.\n");

	rc = rpc_db_dump_async(dmCtx, "", dumpReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register DUMP request.\n");
	printf("DUMP request registered.\n");

	rc = rpc_db_list_async(dmCtx, 1, "", listReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register LIST request.\n");
	printf("LIST request registered.\n");
}

static uint32_t
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__((unused)))
{
	if (event != DMCONFIG_CONNECTED) {
		fprintf(stderr, "Connecting socket unsuccessful.\n");
		return RC_ERR_MISC;
	}
	printf("Socket connected.\n");

	if (rpc_startsession_async(dmCtx, CMD_FLAG_CONFIGURE, 20, sessionStarted, NULL)) {
		fprintf(stderr, "Couldn't register start session request.\n");
		return RC_ERR_MISC;
	}
	printf("Start session request registered.\n");

	return RC_OK;
}

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
	struct ev_loop *loop = EV_DEFAULT;

	DMCONTEXT *dmCtx;
	uint32_t rc;

	dmCtx = dm_context_new();
	if (!dmCtx) {
		fprintf(stderr, "Couldn't create dmconfig context.\n");
		return 0;
	}

	dm_context_init(dmCtx, EV_A, AF_INET, NULL, socketConnected, NULL);

	rc = dm_connect_async(dmCtx);
	if (rc != RC_OK) {
		fprintf(stderr, "Couldn't register connect callback or connecting unsuccessful.\n");
		dm_context_shutdown(dmCtx, DMCONFIG_OK);
		return 0;
	}
	printf("Connect callback registered.\n");

	ev_run(EV_A_ 0);

	dm_context_shutdown(dmCtx, DMCONFIG_OK);
	printf("Socket shut down.\n");

	return 0;
}

