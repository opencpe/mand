/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the server for the client
 *
 * the main request handler switch and the argument demarshaling
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm_dmclient_rpc_skel.h"
#include "dm_dmclient_rpc_impl.h"

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmcontext.h"
#include "libdmconfig/codes.h"

#define BLOCK_ALLOC 16

static inline uint32_t
rpc_client_active_notify_skel(void *ctx, DM2_AVPGRP *obj)
{
	return rpc_client_active_notify(ctx, obj);
}

static inline uint32_t
rpc_client_event_broadcast_skel(void *ctx, DM2_AVPGRP *obj)
{
	uint32_t rc;
	char *path;
	uint32_t type;

	if ((rc = dm_expect_string_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_uint32_type(obj, AVP_EVENT_TYPE, VP_TRAVELPING, &type)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_client_event_broadcast(ctx, path, type);
}

static inline uint32_t
rpc_agent_firmware_download_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	char *address;
	uint8_t credentialstype;
	char *credential;
	char *install_target;
	uint32_t timeframe;
	uint8_t retry_count;
	uint32_t retry_interval;
	uint32_t retry_interval_increment;

	if ((rc = dm_expect_string_type(obj, AVP_STRING, VP_TRAVELPING, &address)) != RC_OK
	    || (rc = dm_expect_uint8_type(obj, AVP_UINT8, VP_TRAVELPING, &credentialstype)) != RC_OK
	    || (rc = dm_expect_string_type(obj, AVP_STRING, VP_TRAVELPING, &credential)) != RC_OK
	    || (rc = dm_expect_string_type(obj, AVP_STRING, VP_TRAVELPING, &install_target)) != RC_OK
	    || (rc = dm_expect_uint32_type(obj, AVP_UINT32, VP_TRAVELPING, &timeframe)) != RC_OK
	    || (rc = dm_expect_uint8_type(obj, AVP_UINT8, VP_TRAVELPING, &retry_count)) != RC_OK
	    || (rc = dm_expect_uint32_type(obj, AVP_UINT32, VP_TRAVELPING, &retry_interval)) != RC_OK
	    || (rc = dm_expect_uint32_type(obj, AVP_UINT32, VP_TRAVELPING, &retry_interval_increment)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_agent_firmware_download(ctx, address, credentialstype, credential,
					   install_target, timeframe, retry_count,
					   retry_interval, retry_interval_increment, answer);
}

static inline uint32_t
rpc_agent_firmware_commit_skel(void *ctx, DM2_AVPGRP *obj)
{
	uint32_t rc;
	int32_t job_id;

	if ((rc = dm_expect_int32_type(obj, AVP_INT32, VP_TRAVELPING, &job_id)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_agent_firmware_commit(ctx, job_id);
}

static inline uint32_t
rpc_agent_set_boot_order_skel(void *ctx, DM2_AVPGRP *obj)
{
	uint32_t rc;
	int pcnt;
	char **boot_order = NULL;

	pcnt = 0;
	do {
		if ((pcnt % BLOCK_ALLOC) == 0)
			if (!(boot_order = talloc_realloc(NULL, boot_order, char *, pcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_string_type(obj, AVP_STRING, VP_TRAVELPING, &boot_order[pcnt])) != RC_OK)
			break;
		pcnt++;
	} while (dm_expect_end(obj) != RC_OK);

	if (rc == RC_OK)
		rc = rpc_agent_set_boot_order(ctx, pcnt, (const char **)boot_order);

	talloc_free(boot_order);
	return rc;
}

uint32_t
rpc_dmclient_switch(void *ctx, const DMC_REQUEST *req, DM2_AVPGRP *obj __attribute__((unused)), DM2_REQUEST **answer)
{
	uint32_t rc;
	size_t pos;

	/* one way requests */
	switch (req->code) {
	case CMD_CLIENT_ACTIVE_NOTIFY:
		return rpc_client_active_notify_skel(ctx, obj);
	case CMD_CLIENT_EVENT_BROADCAST:
		return rpc_client_event_broadcast_skel(ctx, obj);
	}

	if (!(*answer = dm_new_request(ctx, req->code, 0, req->hop2hop, req->end2end)))
		return RC_ERR_ALLOC;

	/* make the RC the first AVP and remember it's position */
	if ((rc = dm_add_uint32_get_pos(*answer, AVP_RC, VP_TRAVELPING, RC_OK, &pos)) != RC_OK)
		return rc;

	switch (req->code) {
	case CMD_FIRMWARE_DOWNLOAD:
		rpc_agent_firmware_download_skel(ctx, obj, *answer);
		break;

	case CMD_FIRMWARE_COMMIT:
		rpc_agent_firmware_commit_skel(ctx, obj);
		break;

	case CMD_SET_BOOT_ORDER:
		rpc_agent_set_boot_order_skel(ctx, obj);
		break;

	default:
		rc = RC_ERR_CONNECTION;
		break;
	}

	if (rc != RC_ERR_ALLOC) {
		/* fill in the RC */
		dm_put_uint32_at_pos(*answer, pos, rc);
		return dm_finalize_packet(*answer);
	}

	return rc;
}
