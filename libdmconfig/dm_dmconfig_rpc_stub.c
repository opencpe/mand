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

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmcontext.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/codes.h"

#include "dm_dmconfig_rpc_stub.h"

uint32_t rpc_startsession_async(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_STARTSESSION, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_uint32(req, AVP_UINT32, VP_TRAVELPING, flags)) != RC_OK
	    || (rc = dm_add_int32(req, AVP_INT32, VP_TRAVELPING, timeout)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_switchsession_async(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_SWITCHSESSION, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_uint32(req, AVP_UINT32, VP_TRAVELPING, flags)) != RC_OK
	    || (rc = dm_add_int32(req, AVP_INT32, VP_TRAVELPING, timeout)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_endsession_async(DMCONTEXT *ctx)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_ENDSESSION, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, NULL, NULL);
}

uint32_t rpc_sessioninfo_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_SESSIONINFO, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_cfgsessioninfo_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_CFGSESSIONINFO, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_subscribe_notify_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_SUBSCRIBE_NOTIFY, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_unsubscribe_notify_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_UNSUBSCRIBE_NOTIFY, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_param_notify_async(DMCONTEXT *ctx, uint32_t notify, int pcnt, const char **paths, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;
	int i;

	if (!(req = dm_new_request(ctx, CMD_PARAM_NOTIFY, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_uint8(req, AVP_BOOL, VP_TRAVELPING, notify)) != RC_OK
	    || (rc = dm_add_object(req)) != RC_OK)
		return rc;

	for (i = 0; i < pcnt; i++)
		if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, paths[i])) != RC_OK)
			return rc;

	if ((rc = dm_finalize_group(req)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_recursive_param_notify_async(DMCONTEXT *ctx, uint32_t notify, const char *path, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_RECURSIVE_PARAM_NOTIFY, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_uint8(req, AVP_BOOL, VP_TRAVELPING, notify)) != RC_OK
	    || (rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_get_passive_notifications_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_GET_PASSIVE_NOTIFICATIONS, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_addinstance_async(DMCONTEXT *ctx, const char *path, uint16_t id, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_ADDINSTANCE, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_add_uint16(req, AVP_UINT16, VP_TRAVELPING, id)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_delinstance_async(DMCONTEXT *ctx, const char *path, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_DELINSTANCE, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_set_async(DMCONTEXT *ctx, int pvcnt, struct rpc_db_set_path_value *values, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;
	int i;

	if (!(req = dm_new_request(ctx, CMD_DB_SET, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	for (i = 0; i < pvcnt; i++) {
		if ((rc = dm_add_object(req)) != RC_OK
		    || (rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, values[i].path)) != RC_OK
		    || (rc = dm_add_raw(req, values[i].value.code, values[i].value.vendor_id, values[i].value.data, values[i].value.size)) != RC_OK
		    || (rc = dm_finalize_group(req)) != RC_OK)
			return rc;
	}

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_get_async(DMCONTEXT *ctx, int pcnt, const char **paths, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;
	int i;

	if (!(req = dm_new_request(ctx, CMD_DB_GET, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	for (i = 0; i < pcnt; i++)
		if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, paths[i])) != RC_OK)
			return rc;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_list_async(DMCONTEXT *ctx, int level, const char *path, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_LIST, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_uint16(req, AVP_UINT16, VP_TRAVELPING, level)) != RC_OK
	    || (rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_retrieve_enum_async(DMCONTEXT *ctx, const char *path, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_RETRIEVE_ENUMS, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_dump_async(DMCONTEXT *ctx, const char *path, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_DUMP, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_save_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_SAVE, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_commit_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_COMMIT, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_cancel_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_CANCEL, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

uint32_t rpc_db_findinstance_async(DMCONTEXT *ctx, const const char *path, const char *name, const struct dm2_avp *search, DMRESULT_CB cb, void *data)
{
	uint32_t rc;
	DM2_REQUEST *req;

	if (!(req = dm_new_request(ctx, CMD_DB_FINDINSTANCE, CMD_FLAG_REQUEST, 0, 0)))
		return RC_ERR_ALLOC;

	if ((rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, path)) != RC_OK
	    || (rc = dm_add_string(req, AVP_PATH, VP_TRAVELPING, name)) != RC_OK
	    || (rc = dm_add_raw(req, search->code, search->vendor_id, search->data, search->size)) != RC_OK
	    || (rc = dm_finalize_packet(req)) != RC_OK)
		return rc;

	return dm_enqueue_request(ctx, req, cb, data);
}

/*
 * sync call wrapper's
 */

uint32_t rpc_startsession(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_startsession_async(ctx, flags, timeout, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_switchsession(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_switchsession_async(ctx, flags, timeout, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_endsession(DMCONTEXT *ctx)
{
	rpc_endsession_async(ctx);
	ev_run(ctx->ev, 0);

	return RC_OK;
}

uint32_t rpc_sessioninfo(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_sessioninfo_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_cfgsessioninfo(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_cfgsessioninfo_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_subscribe_notify(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_subscribe_notify_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_unsubscribe_notify(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_unsubscribe_notify_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_param_notify(DMCONTEXT *ctx, uint32_t notify, int pcnt, const char **paths, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_param_notify_async(ctx, notify, pcnt, paths, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_recursive_param_notify(DMCONTEXT *ctx, uint32_t notify, const char *path, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_recursive_param_notify_async(ctx, notify, path, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_get_passive_notifications(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_get_passive_notifications_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_addinstance(DMCONTEXT *ctx, const char *path, uint16_t id, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_addinstance_async(ctx, path, id, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_delinstance(DMCONTEXT *ctx, const char *path, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_delinstance_async(ctx, path, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_set(DMCONTEXT *ctx, int pvcnt, struct rpc_db_set_path_value *values, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_set_async(ctx, pvcnt, values, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_get(DMCONTEXT *ctx, int pcnt, const char **paths, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_get_async(ctx, pcnt, paths, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_list(DMCONTEXT *ctx, int level, const char *path, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_list_async(ctx, level, path, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_retrieve_enum(DMCONTEXT *ctx, const char *path, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_retrieve_enum_async(ctx, path, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_dump(DMCONTEXT *ctx, const char *path, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_dump_async(ctx, path, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_save(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_save_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_commit(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_commit_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_cancel(DMCONTEXT *ctx, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_cancel_async(ctx, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

uint32_t rpc_db_findinstance(DMCONTEXT *ctx, const const char *path, const char *name, const struct dm2_avp *search, DM2_AVPGRP *answer)
{
	struct async_reply reply = {.rc = RC_OK, .answer = answer };

	rpc_db_findinstance_async(ctx, path, name, search, dm_async_cb, &reply);
	ev_run(ctx->ev, 0);

	return reply.rc;
}

