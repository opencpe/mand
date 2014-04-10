/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the client for the server
 *
 * the main request handler switch and the argument demarshaling
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* #include "dm_dmconfig.h" */
#include "dm_dmconfig_rpc_skel.h"
#include "dm_dmconfig_rpc_impl.h"

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

#include <mand/dm_token.h>
#include "mand/dm_strings.h"

#define BLOCK_ALLOC 16

static uint32_t
dm_expect_path_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, dm_selector *value)
{
	uint32_t r = RC_OK;
	char *s;

	if ((r = dm_expect_string_type(grp, exp_code, exp_vendor_id, &s)) != RC_OK)
		return r;

	if (!dm_name2sel(s, value))
		r = RC_ERR_MISC;

	talloc_free(s);
	return r;
}

static inline uint32_t
rpc_startsession_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	uint32_t flags;
	int32_t timeout;

	if ((rc = dm_expect_uint32_type(obj, AVP_UINT32, VP_TRAVELPING, &flags)) != RC_OK
	    || (rc = dm_expect_int32_type(obj, AVP_INT32, VP_TRAVELPING, &timeout)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_startsession(ctx, flags, timeout, answer);
}

static inline uint32_t
rpc_switchsession_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	uint32_t flags;
	int32_t timeout;

	if ((rc = dm_expect_uint32_type(obj, AVP_UINT32, VP_TRAVELPING, &flags)) != RC_OK
	    || (rc = dm_expect_int32_type(obj, AVP_INT32, VP_TRAVELPING, &timeout)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_switchsession(ctx, flags, timeout, answer);
}

static inline uint32_t
rpc_endsession_skel(void *ctx, DM2_AVPGRP *obj)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_endsession(ctx);
}

static inline uint32_t
rpc_sessioninfo_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_sessioninfo(ctx, answer);
}

static inline uint32_t
rpc_cfgsessioninfo_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_cfgsessioninfo(ctx, answer);
}

static inline uint32_t
rpc_subscribe_notify_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_subscribe_notify(ctx, answer);
}

static inline uint32_t
rpc_unsubscribe_notify_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_unsubscribe_notify(ctx, answer);
}


static inline uint32_t
rpc_param_notify_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	uint8_t notify;
	DM2_AVPGRP grp;
	DM2_AVPGRP parms;
	int pcnt;
	dm_selector *path = NULL;

	if ((rc = dm_expect_uint8_type(&grp, AVP_NOTIFY_LEVEL, VP_TRAVELPING, &notify)) != RC_OK
	    || (rc = dm_expect_object(&grp, &parms)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	pcnt = 0;
	do {
		if ((pcnt % BLOCK_ALLOC) == 0)
			if (!(path = talloc_realloc(NULL, path, dm_selector, pcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_path_type(&parms, AVP_PATH, VP_TRAVELPING, &path[pcnt])) != RC_OK)
			break;
		pcnt++;
	} while (dm_expect_end(obj) != RC_OK);

	if (rc == RC_OK)
		rc = rpc_param_notify(ctx, notify, pcnt, path, answer);

	talloc_free(path);
	return rc;
}

static inline uint32_t
rpc_recursive_param_notify_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	uint8_t notify;
	dm_selector path;

	if ((rc = dm_expect_uint8_type(obj, AVP_NOTIFY_LEVEL, VP_TRAVELPING, &notify)) != RC_OK
	    || (rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_recursive_param_notify(ctx, notify, path, answer);
}

static inline uint32_t
rpc_get_passive_notifications_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_get_passive_notifications(ctx, answer);
}

static inline uint32_t
rpc_db_addinstance_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	dm_selector path;
	dm_id id;

	if ((rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_uint16_type(obj, AVP_UINT16, VP_TRAVELPING, &id)) != RC_OK)
		return rc;

	return rpc_db_addinstance(ctx, path, id, answer);
}

static inline uint32_t
rpc_db_delinstance_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	dm_selector path;

	if ((rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK)
		return rc;

	return rpc_db_delinstance(ctx, path, answer);
}

static inline uint32_t
rpc_db_set_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	int pvcnt = 0;
	struct rpc_db_set_path_value *values = NULL;

	pvcnt = 0;
	do {
		DM2_AVPGRP grp;

		if ((pvcnt % BLOCK_ALLOC) == 0)
			if (!(values = talloc_realloc(NULL, values, struct rpc_db_set_path_value, pvcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_object(obj, &grp)) != RC_OK
		    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &values[pvcnt].path)) != RC_OK
		    || (rc = dm_expect_value(&grp, &values[pvcnt].value)) != RC_OK
		    || (rc = dm_expect_group_end(&grp)) != RC_OK)
		    return rc;

		pvcnt++;
	} while (dm_expect_end(obj) != RC_OK);

	rc = rpc_db_set(ctx, pvcnt, values, answer);

	talloc_free(values);
	return rc;
}

static inline uint32_t
rpc_db_get_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	int pcnt;
	dm_selector *values = NULL;

	pcnt = 0;
	do {
		if ((pcnt % BLOCK_ALLOC) == 0)
			if (!(values = talloc_realloc(NULL, values, dm_selector, pcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, values + pcnt)) != RC_OK)
			break;

		pcnt++;
	} while (dm_expect_end(obj) != RC_OK);

	if (rc == RC_OK)
		rc = rpc_db_get(ctx, pcnt, values, answer);

	talloc_free(values);
	return rc;
}

static inline uint32_t
rpc_db_list_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	uint16_t level;
	dm_selector path;

	if ((rc = dm_expect_uint16_type(obj, AVP_UINT16, VP_TRAVELPING, &level)) != RC_OK
	    || (rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_list(ctx, level, path, answer);
}

static inline uint32_t
rpc_db_retrieve_enum_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	dm_selector path;

	if ((rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
				return rc;

	return rpc_db_retrieve_enum(ctx, path, answer);
}

static inline uint32_t
rpc_db_dump_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	char *path;

	if ((rc = dm_expect_string_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_dump(ctx, path, answer);
}

static inline uint32_t
rpc_db_save_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_save(ctx, answer);
}

static inline uint32_t
rpc_db_commit_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_commit(ctx, answer);
}

static inline uint32_t
rpc_db_cancel_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_cancel(ctx, answer);
}

static inline uint32_t
rpc_db_findinstance_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
	uint32_t rc;
	dm_selector path;
	struct dm_bin name;
	struct dm2_avp value;

	if ((rc = dm_expect_path_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK		/* path of table */
	    || (rc = dm_expect_bin(obj, AVP_PATH, VP_TRAVELPING, &name)) != RC_OK		/* name of paramter to check (last part of path) */
	    || (rc = dm_expect_value(obj, &value)) != RC_OK					/* value to look for (type is AVP code) */
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_findinstance(ctx, path, &name, &value, answer);
}

uint32_t
rpc_dmconfig_switch(void *ctx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM2_REQUEST **answer)
{
	uint32_t rc;
	size_t pos;

	/* one way requests */
	switch (req->code) {
	case CMD_ENDSESSION:
		return rpc_endsession_skel(ctx, obj);
	}

	if (!(*answer = dm_new_request(ctx, req->code, 0, req->hop2hop, req->end2end)))
		return RC_ERR_ALLOC;

	/* make the RC the first AVP and remember it's position */
	if ((rc = dm_add_uint32_get_pos(*answer, AVP_RC, VP_TRAVELPING, RC_OK, &pos)) != RC_OK)
		return rc;

	switch (req->code) {
	case CMD_STARTSESSION:
		rc = rpc_startsession_skel(ctx, obj, *answer);
		break;

	case CMD_SWITCHSESSION:
		rc = rpc_switchsession_skel(ctx, obj, *answer);
		break;

	case CMD_SESSIONINFO:
		rc = rpc_sessioninfo_skel(ctx, obj, *answer);
		break;

	case CMD_CFGSESSIONINFO:
		rc = rpc_cfgsessioninfo_skel(ctx, obj, *answer);
		break;

	case CMD_SUBSCRIBE_NOTIFY:
		rc = rpc_subscribe_notify_skel(ctx, obj, *answer);
		break;

	case CMD_UNSUBSCRIBE_NOTIFY:
		rc = rpc_unsubscribe_notify_skel(ctx, obj, *answer);
		break;

	case CMD_PARAM_NOTIFY:
		rc = rpc_param_notify_skel(ctx, obj, *answer);
		break;

	case CMD_RECURSIVE_PARAM_NOTIFY:
		rc = rpc_recursive_param_notify_skel(ctx, obj, *answer);
		break;

	case CMD_GET_PASSIVE_NOTIFICATIONS:
		rc = rpc_get_passive_notifications_skel(ctx, obj, *answer);
		break;

	case CMD_DB_ADDINSTANCE:
		rc = rpc_db_addinstance_skel(ctx, obj, *answer);
		break;

	case CMD_DB_DELINSTANCE:
		rc = rpc_db_delinstance_skel(ctx, obj, *answer);
		break;

	case CMD_DB_SET:
		rc = rpc_db_set_skel(ctx, obj, *answer);
		break;

	case CMD_DB_GET:
		rc = rpc_db_get_skel(ctx, obj, *answer);
		break;

	case CMD_DB_LIST:
		rc = rpc_db_list_skel(ctx, obj, *answer);
		break;

	case CMD_DB_RETRIEVE_ENUMS:
		rc = rpc_db_retrieve_enum_skel(ctx, obj, *answer);
		break;

	case CMD_DB_DUMP:
		rc = rpc_db_dump_skel(ctx, obj, *answer);
		break;

	case CMD_DB_SAVE:
		rc = rpc_db_save_skel(ctx, obj, *answer);
		break;

	case CMD_DB_COMMIT:
		rc = rpc_db_commit_skel(ctx, obj, *answer);
		break;

	case CMD_DB_CANCEL:
		rc = rpc_db_cancel_skel(ctx, obj, *answer);
		break;

	case CMD_DB_FINDINSTANCE:
		rc = rpc_db_findinstance_skel(ctx, obj, *answer);
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
