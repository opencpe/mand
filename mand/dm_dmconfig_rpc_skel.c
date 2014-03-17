/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm_dmconfig.h"
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

#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmmsg.h"
#include "libdmconfig/codes.h"

#include "dm.h"
#include "dmd.h"
#include "dm_token.h"
#include "dm_store.h"
#include "dm_index.h"
#include "dm_cache.h"
#include "dm_serialize.h"
#include "dm_cfgsessions.h"
#include "dm_strings.h"
#include "dm_cfg_bkrst.h"
#include "dm_notify.h"
#include "dm_dmconfig.h"
#include "dm_validate.h"

#define BLOCK_ALLOC 16

static inline uint32_t
rpc_startsession_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;
	DM2_AVPGRP grp;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_startsession(sockCtx, req, &grp);
}

static inline uint32_t
rpc_switchsession_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;
	DM2_AVPGRP grp;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_switchsession(sockCtx, req, &grp);
}

static inline uint32_t
rpc_endsession_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_endsession(sockCtx, req);
}

static inline uint32_t
rpc_sessioninfo_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_sessioninfo(sockCtx, req, answer);
}

static inline uint32_t
rpc_cfgsessioninfo_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_cfgsessioninfo(sockCtx, req, answer);
}

static inline uint32_t
rpc_subscribe_notify_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_subscribe_notify(sockCtx, req);
}

static inline uint32_t
rpc_unsubscribe_notify_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_unsubscribe_notify(sockCtx, req);
}


static inline uint32_t
rpc_param_notify_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;
	uint8_t notify;
	DM2_AVPGRP grp;
	DM2_AVPGRP parms;
	int pcnt;
	dm_selector *path = NULL;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_uint8_type(&grp, AVP_BOOL, VP_TRAVELPING, &notify)) != RC_OK
	    || (rc = dm_expect_object(&grp, &parms)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	pcnt = 0;
	do {
		if ((pcnt % BLOCK_ALLOC) == 0)
			if (!(path = talloc_realloc(req->ctx, path, dm_selector, pcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_path_type(&parms, AVP_PATH, VP_TRAVELPING, &path[pcnt])) != RC_OK)
			break;
		pcnt++;
	} while (rc == RC_OK);

	return rpc_param_notify(sockCtx, req, notify, pcnt, path);
}

static inline uint32_t
rpc_recursive_param_notify_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;
	uint8_t notify;
	DM2_AVPGRP grp;
	DM2_AVPGRP parm;
	dm_selector path;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_uint8_type(&grp, AVP_BOOL, VP_TRAVELPING, &notify)) != RC_OK
	    || (rc = dm_expect_object(&grp, &parm)) != RC_OK
	    || (rc = dm_expect_path_type(&parm, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_recursive_param_notify(sockCtx, req, notify, path);
}

static inline uint32_t
rpc_get_passive_notifications_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_get_passive_notifications(sockCtx, req, answer);
}

static inline uint32_t
rpc_db_addinstance_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;
	DM2_AVPGRP grp;
	dm_selector path;
	dm_id id;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_uint16_type(&grp, AVP_UINT16, VP_TRAVELPING, &id)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_db_addinstance(sockCtx, req, path, id, answer);
}

static inline uint32_t
rpc_db_delinstance_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;
	DM2_AVPGRP grp;
	dm_selector path;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_delinstance(sockCtx, req, path);
}

static inline uint32_t
rpc_db_set_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;
	DM2_AVPGRP grp;
	int pvcnt = 0;
	struct rpc_db_set_path_value *values;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK)
		return rc;

	pvcnt = 0;
	do {
		if ((pvcnt % BLOCK_ALLOC) == 0)
			if (!(values = talloc_realloc(req->ctx, values, struct rpc_db_set_path_value, pvcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &values[pvcnt].path)) != RC_OK)
			return rc;
		if ((rc = dm_expect_value(&grp, &values[pvcnt].value)) != RC_OK)
			break;
		pvcnt++;
	} while (rc == RC_OK);

	return rpc_db_set(sockCtx, req, pvcnt, values);
}

static inline uint32_t
rpc_db_get_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;
	DM2_AVPGRP grp;
	int pcnt;
	struct path_type *values;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK)
				return rc;

	pcnt = 0;
	do {
		void *data;
		size_t size;
		char str[1024];

		if ((pcnt % BLOCK_ALLOC) == 0)
			if (!(values = talloc_realloc(req->ctx, values, struct path_type, pcnt + BLOCK_ALLOC)))
				return RC_ERR_ALLOC;

		if ((rc = dm_expect_raw(&grp, AVP_TYPE_PATH, VP_TRAVELPING, &data, &size)) != RC_OK)
			break;

		if (size <= sizeof(uint32_t) || size > sizeof(str))
			return RC_ERR_MISC;

		values[pcnt].type = dm_get_uint32_avp(data);

		strncpy(str, data + sizeof(uint32_t), size - sizeof(uint32_t));
		if (!dm_name2sel(str, &values[pcnt].path))
			    return RC_ERR_MISC;

		pcnt++;
	} while (rc == RC_OK);

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_db_get(sockCtx, req, pcnt, values, answer);
}

static inline uint32_t
rpc_db_list_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;
	DM2_AVPGRP grp;
	uint16_t level;
	dm_selector path;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_uint16_type(&grp, AVP_UINT16, VP_TRAVELPING, &level)) != RC_OK
	    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(&grp)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_db_list(sockCtx, req, level, path, answer);
}

static inline uint32_t
rpc_db_retrieve_enum_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;
	DM2_AVPGRP grp;
	dm_selector path;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(&grp)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
				return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_db_retrieve_enum(sockCtx, req, path, answer);
}

static inline uint32_t
rpc_db_dump_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;
	DM2_AVPGRP grp;
	dm_selector path;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK
	    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_end(&grp)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_db_dump(sockCtx, req, path, answer);
}

static inline uint32_t
rpc_db_save_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_save(sockCtx, req);
}

static inline uint32_t
rpc_db_commit_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_commit(sockCtx, req);
}

rpc_db_cancel_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer __attribute__((unused)))
{
	uint32_t rc;

	if ((rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_db_cancel(sockCtx, req);
}

static inline uint32_t
rpc_db_findinstance_skel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	uint32_t rc;
	DM2_AVPGRP grp;
	dm_selector path;
	struct dm_bin name;
	struct dm2_avp value;

	if ((rc = dm_expect_object(obj, &grp)) != RC_OK						/* parameter/value container */
	    || (rc = dm_expect_path_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK	/* path of table */
	    || (rc = dm_expect_bin(&grp, AVP_PATH, VP_TRAVELPING, &name)) != RC_OK		/* name of paramter to check (last part of path) */
	    || (rc = dm_expect_value(&grp, &value)) != RC_OK					/* value to look for (type is AVP code) */
	    || (rc = dm_expect_end(&grp)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	if (!(*answer = new_dm_avpgrp(req->ctx)))
		return RC_ERR_ALLOC;

	return rpc_db_findinstance(sockCtx, req, path, &name, &value, answer);
}

uint32_t
rpc_dmconfig_switch(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer)
{
	switch (req->code) {
	case CMD_STARTSESSION:
		return rpc_startsession_skel(sockCtx, req, obj, answer);

	case CMD_SWITCHSESSION:
		return rpc_switchsession_skel(sockCtx, req, obj, answer);

	case CMD_ENDSESSION:
		return rpc_endsession_skel(sockCtx, req, obj, answer);

	case CMD_SESSIONINFO:
		return rpc_sessioninfo_skel(sockCtx, req, obj, answer);

	case CMD_CFGSESSIONINFO:
		return rpc_cfgsessioninfo_skel(sockCtx, req, obj, answer);

	case CMD_SUBSCRIBE_NOTIFY:
		return rpc_subscribe_notify_skel(sockCtx, req, obj, answer);

	case CMD_UNSUBSCRIBE_NOTIFY:
		return rpc_unsubscribe_notify_skel(sockCtx, req, obj, answer);

	case CMD_PARAM_NOTIFY:
		return rpc_param_notify_skel(sockCtx, req, obj, answer);

	case CMD_RECURSIVE_PARAM_NOTIFY:
		return rpc_recursive_param_notify_skel(sockCtx, req, obj, answer);

	case CMD_GET_PASSIVE_NOTIFICATIONS:
		return rpc_get_passive_notifications_skel(sockCtx, req, obj, answer);

	case CMD_DB_ADDINSTANCE:
		return rpc_db_addinstance_skel(sockCtx, req, obj, answer);

	case CMD_DB_DELINSTANCE:
		return rpc_db_delinstance_skel(sockCtx, req, obj, answer);

	case CMD_DB_SET:
		return rpc_db_set_skel(sockCtx, req, obj, answer);

	case CMD_DB_GET:
		return rpc_db_get_skel(sockCtx, req, obj, answer);

	case CMD_DB_LIST:
		return rpc_db_list_skel(sockCtx, req, obj, answer);

	case CMD_DB_RETRIEVE_ENUMS:
		return rpc_db_retrieve_enum_skel(sockCtx, req, obj, answer);

	case CMD_DB_DUMP:
		return rpc_db_dump_skel(sockCtx, req, obj, answer);

	case CMD_DB_SAVE:
		return rpc_db_save_skel(sockCtx, req, obj, answer);

	case CMD_DB_COMMIT:
		return rpc_db_commit_skel(sockCtx, req, obj, answer);

	case CMD_DB_CANCEL:
		return rpc_db_cancel_skel(sockCtx, req, obj, answer);

	case CMD_DB_FINDINSTANCE:
		return rpc_db_findinstance_skel(sockCtx, req, obj, answer);

	default:
		return RC_ERR_CONNECTION;
	}
}
