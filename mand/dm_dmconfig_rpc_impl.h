/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DM_DMCONFIG_RPC_IMPL_H
#define DM_DMCONFIG_RPC_IMPL_H

#include "dm_dmconfig_rpc_skel.h"

uint32_t rpc_startsession(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *grp);
uint32_t rpc_switchsession(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *grp);
uint32_t rpc_endsession(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req);
uint32_t rpc_sessioninfo(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM_OBJ **answer);
uint32_t rpc_cfgsessioninfo(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM_OBJ **answer);
uint32_t rpc_subscribe_notify(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req);
uint32_t rpc_unsubscribe_notify(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req);
uint32_t rpc_param_notify(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, uint32_t notify, int pcnt, dm_selector *path);
uint32_t rpc_recursive_param_notify(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, uint32_t notify, dm_selector path);
uint32_t rpc_get_passive_notifications(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM_OBJ **answer);
uint32_t rpc_db_addinstance(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, dm_selector path, dm_id id, DM_OBJ **answer);
uint32_t rpc_db_delinstance(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, dm_selector path);
uint32_t rpc_db_set(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, int pvcnt, struct rpc_db_set_path_value *values);
uint32_t rpc_db_get(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, int pcnt, struct path_type *values, DM_OBJ **answer);
uint32_t rpc_db_list(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, int level, dm_selector path, DM_OBJ **answer);
uint32_t rpc_db_retrieve_enum(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, dm_selector path, DM_OBJ **answer);
uint32_t rpc_db_dump(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, dm_selector path, DM_OBJ **answer);
uint32_t rpc_db_save(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req);
uint32_t rpc_db_commit(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req);
uint32_t rpc_db_cancel(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req);
uint32_t rpc_db_findinstance(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, const dm_selector path, const struct dm_bin *name, const struct dm2_avp *search, DM_OBJ **answer);

#endif
