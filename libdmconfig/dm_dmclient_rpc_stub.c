/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the server to the client
 *
 * implementation of the server stub's
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#include <ralloc.h>

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmcontext.h"
#include "libdmconfig/codes.h"

#include "mand/dm_token.h"

#include "dm_dmclient_rpc_stub.h"

/*
 * RPC stub's
 */

uint32_t rpc_event_broadcast(DMCONTEXT *ctx, const char *path, uint32_t type)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_CLIENT_EVENT_BROADCAST, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_add_uint32(req, AVP_EVENT_TYPE, VP_TRAVELPING, type)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue(ctx, req, ONE_WAY, NULL, NULL);

}

uint32_t rpc_get_interface_state_async(DMCONTEXT *ctx, const char *if_name, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_CLIENT_GET_INTERFACE_STATE, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_STRING, VP_TRAVELPING, if_name)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_agent_firmware_download_async(DMCONTEXT *ctx, const char *address, uint8_t credentialstype, const char *credential,
				     const char *install_target, uint32_t timeframe, uint8_t retry_count,
				     uint32_t retry_interval, uint32_t retry_interval_increment,
				     DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_FIRMWARE_DOWNLOAD, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_STRING, VP_TRAVELPING, address)) != RC_OK
	    || (rc = dm_add_uint8(req, AVP_UINT8, VP_TRAVELPING, credentialstype)) != RC_OK
	    || (rc = dm_add_string(req, AVP_STRING, VP_TRAVELPING, credential)) != RC_OK
	    || (rc = dm_add_string(req, AVP_STRING, VP_TRAVELPING, install_target)) != RC_OK
	    || (rc = dm_add_uint32(req, AVP_UINT32, VP_TRAVELPING, timeframe)) != RC_OK
	    || (rc = dm_add_uint8(req, AVP_UINT8, VP_TRAVELPING, retry_count)) != RC_OK
	    || (rc = dm_add_uint32(req, AVP_UINT32, VP_TRAVELPING, retry_interval)) != RC_OK
	    || (rc = dm_add_uint32(req, AVP_UINT32, VP_TRAVELPING, retry_interval_increment)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_agent_firmware_commit_async(DMCONTEXT *ctx, int32_t job_id, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_FIRMWARE_COMMIT, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_int32(req, AVP_INT32, VP_TRAVELPING, job_id)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_agent_set_boot_order_async(DMCONTEXT *ctx, int pcnt, const char **boot_order, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;
	int i;

	if (!(req = dm_new_request(ctx, CMD_SET_BOOT_ORDER, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	for (i = 0; i < pcnt; i++)
		if ((rc = dm_add_string(req, AVP_STRING, VP_TRAVELPING, boot_order[i])) != RC_OK)
			return rc;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

/*
 * sync call wrapper's
 */

uint32_t rpc_get_interface_state(DMCONTEXT *ctx, const char *if_name, DM2_AVPGRP *answer)
{
        struct async_reply reply = {.rc = RC_OK, .answer = answer };

        rpc_get_interface_state_async(ctx, if_name, dm_async_cb, &reply);
        ev_run(ctx->ev, 0);

        return reply.rc;
}

uint32_t rpc_agent_firmware_download(DMCONTEXT *ctx, const char *address, uint8_t credentialstype, const char *credential,
				    const char *install_target, uint32_t timeframe, uint8_t retry_count,
				    uint32_t retry_interval, uint32_t retry_interval_increment,
				    DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_agent_firmware_download_async(ctx, address, credentialstype, credential, install_target,
				    timeframe, retry_count, retry_interval, retry_interval_increment,
				    dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_agent_firmware_commit(DMCONTEXT *ctx, int32_t job_id)
{
	struct async_reply reply = {.rc = RC_OK, .answer = NULL };

	rpc_agent_firmware_commit_async(ctx, job_id, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_agent_set_boot_order(DMCONTEXT *ctx, int pcnt, const char **boot_order)
{
	struct async_reply reply = {.rc = RC_OK, .answer = NULL };

	rpc_agent_set_boot_order_async(ctx, pcnt, boot_order, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}
