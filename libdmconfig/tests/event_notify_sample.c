/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * libdmconfig client lib sample: uses the nonblocking libev-based API
 * for notifications
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
#include <libdmconfig/dm_dmclient_rpc_impl.h>

#define CB_ERR(...) do {		\
	fprintf(stderr, __VA_ARGS__);	\
	return;				\
} while (0)

/** changing this parameter triggers the shutdown process */
#define SHUTDOWN_PARAMETER "system-state.platform.machine"

static void
request_cb(DMCONTEXT *socket, DM_PACKET *pkt, DM2_AVPGRP *grp, void *userdata __attribute__((unused)))
{
	DMC_REQUEST req;
	DM2_REQUEST *answer = NULL;

	req.hop2hop = dm_hop2hop_id(pkt);
	req.end2end = dm_end2end_id(pkt);
	req.code = dm_packet_code(pkt);

	printf("request_cb: received %s",
	       dm_packet_flags(pkt) & CMD_FLAG_REQUEST ? "request" : "answer");
#ifdef LIBDMCONFIG_DEBUG
	dump_dm_packet(pkt);
#endif

	if ((rpc_dmclient_switch(socket, &req, grp, &answer)) == RC_ERR_ALLOC) {
		dm_context_shutdown(socket, DMCONFIG_OK);
		dm_context_release(socket);
		ev_break(socket->ev, EVBREAK_ALL);
		return;
	}

	if (answer)
		dm_enqueue(socket, answer, REPLY, NULL, NULL);
}

void
unsubscribedNotify(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't unsubscribe notifications.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't unsubscribe notifications.\n");
	printf("Unsubscribed notifications.\n");

	rc = rpc_endsession_async(dmCtx);
	if (rc != RC_OK)
		CB_ERR("Couldn't register END SESSION request.\n");
	printf("END SESSION request registered.\n");
}

uint32_t
rpc_client_active_notify(void *ctx, DM2_AVPGRP *obj)
{
	DMCONTEXT *dmCtx = ctx;
	uint32_t rc;

	do {
		DM2_AVPGRP grp;
		uint32_t type;
		char *path;

		if ((rc = dm_expect_object(obj, &grp)) != RC_OK
		    || (rc = dm_expect_uint32_type(&grp, AVP_NOTIFY_TYPE, VP_TRAVELPING, &type)) != RC_OK
		    || (rc = dm_expect_string_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK) {
			fprintf(stderr, "Couldn't decode active notifications, rc=%d\n", rc);
			return rc;
		}

		switch (type) {
		case NOTIFY_INSTANCE_CREATED:
			printf("Notification: Instance \"%s\" created\n", path);
			break;

		case NOTIFY_INSTANCE_DELETED:
			printf("Notification: Instance \"%s\" deleted\n", path);
			break;

		case NOTIFY_PARAMETER_CHANGED: {
			struct dm2_avp avp;
			char *str;

			if ((rc = dm_expect_uint32_type(&grp, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK
			    || (rc = dm_expect_value(&grp, &avp)) != RC_OK
			    || (rc = dm_decode_unknown_as_string(type, avp.data, avp.size, &str)) != RC_OK) {
				fprintf(stderr, "Couldn't decode parameter changed notifications, rc=%d\n", rc);
				return rc;
			}

			printf("Notification: Parameter \"%s\" changed to \"%s\"\n", path, str);

			if (!strcmp(path, SHUTDOWN_PARAMETER)) {
				/*
				 * NOTE: You don't strictly need an unsubscribe before terminating the session!
				 */
				rc = rpc_unsubscribe_notify_async(dmCtx, unsubscribedNotify, NULL);
				if (rc != RC_OK) {
					fprintf(stderr, "Couldn't register UNSUBSCRIBE NOTIFY request.\n");
					return rc;
				}
				printf("Notification unsubscription request registered.\n");
			}

			break;
	        }
		default:
			printf("Notification: Warning, unknown type: %d\n", type);
			break;
		}
	} while ((rc = dm_expect_end(obj)) != RC_OK);

	return dm_expect_end(obj);
}

void
registeredNotify(DMCONTEXT *dmCtx __attribute__((unused)), DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't register parameter notifications.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't register parameter notifications.\n");
	printf("Parameter notifications registered.\n");

	printf("\nThe sample program shuts down when the following parameter is modified: %s\n\n",
	       SHUTDOWN_PARAMETER);
}

void
subscribedNotify(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *answer_grp, void *user_data __attribute__((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Couldn't subscribe notifications.\n");

	uint32_t answer_rc;
	rc = dm_expect_uint32_type(answer_grp, AVP_RC, VP_TRAVELPING, &answer_rc);
	if (rc != RC_OK || answer_rc != RC_OK)
		CB_ERR("Couldn't subscribe notifications.\n");
	printf("Subscribed notifications.\n");

	rc = rpc_recursive_param_notify_async(dmCtx, NOTIFY_ACTIVE, "", registeredNotify, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register RECURSIVE PARAM NOTIFY request.\n");
	printf("RECURSIVE PARAM NOTIFY request registered.\n");
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

	rc = rpc_subscribe_notify_async(dmCtx, subscribedNotify, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't register SUBSCRIBE NOTIFY request.\n");
	printf("Notification subscription request registered.\n");
}

static uint32_t
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__((unused)))
{
	if (event != DMCONFIG_CONNECTED) {
		fprintf(stderr, "Connecting socket unsuccessful.\n");
		return RC_ERR_MISC;
	}
	printf("Socket connected.\n");

	if (rpc_startsession_async(dmCtx, CMD_FLAG_READWRITE, 0, sessionStarted, NULL)) {
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

	dm_context_init(dmCtx, EV_A, AF_INET, NULL, socketConnected, request_cb);

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
