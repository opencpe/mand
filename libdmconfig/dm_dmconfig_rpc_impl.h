/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the client for the server
 *
 * prototypes for the server implementation
 */

#ifndef DM_DMCONFIG_RPC_IMPL_H
#define DM_DMCONFIG_RPC_IMPL_H

#include "mand/dm_token.h"

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dm_dmconfig_rpc_skel.h"

struct rpc_db_set_path_value {
	dm_selector path;
	struct dm2_avp value;
};

uint32_t rpc_startsession(void *ctx, uint32_t flags, int32_t timeout, DM2_REQUEST *answer);
uint32_t rpc_switchsession(void *ctx, uint32_t flags, int32_t timeout, DM2_REQUEST *answer);
uint32_t rpc_endsession(void *ctx);
uint32_t rpc_sessioninfo(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_cfgsessioninfo(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_subscribe_notify(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_unsubscribe_notify(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_param_notify(void *ctx, uint32_t notify, int pcnt, dm_selector *path, DM2_REQUEST *answer);
uint32_t rpc_recursive_param_notify(void *ctx, uint32_t notify, dm_selector path, DM2_REQUEST *answer);
uint32_t rpc_get_passive_notifications(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_db_addinstance(void *ctx, dm_selector path, dm_id id, DM2_REQUEST *answer);
uint32_t rpc_db_delinstance(void *ctx, dm_selector path, DM2_REQUEST *answer);
uint32_t rpc_db_set(void *ctx, int pvcnt, struct rpc_db_set_path_value *values, DM2_REQUEST *answer);
uint32_t rpc_db_get(void *ctx, int pcnt, dm_selector *values, DM2_REQUEST *answer);
uint32_t rpc_db_list(void *ctx, int level, dm_selector path, DM2_REQUEST *answer);
uint32_t rpc_db_retrieve_enum(void *ctx, dm_selector path, DM2_REQUEST *answer);
uint32_t rpc_db_dump(void *ctx, char *path, DM2_REQUEST *answer);
uint32_t rpc_db_save(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_db_commit(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_db_cancel(void *ctx, DM2_REQUEST *answer);
uint32_t rpc_db_findinstance(void *ctx, const dm_selector path, const struct dm_bin *name, const struct dm2_avp *search, DM2_REQUEST *answer);
uint32_t rpc_register_role(void *ctx, const char *role);

#endif
