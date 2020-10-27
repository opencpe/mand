/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the client to the server
 *
 * prototypes for client stub's
 */

#ifndef DM_DMCONFIG_RPC_STUB_H
#define DM_DMCONFIG_RPC_STUB_H

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"

struct rpc_db_set_path_value {
        const char *path;
        struct dm2_avp value;
};

uint32_t rpc_startsession_async(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DMRESULT_CB cb, void *data);
uint32_t rpc_switchsession_async(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DMRESULT_CB cb, void *data);
uint32_t rpc_endsession_async(DMCONTEXT *ctx);
uint32_t rpc_sessioninfo_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_cfgsessioninfo_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_subscribe_notify_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_unsubscribe_notify_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_param_notify_async(DMCONTEXT *ctx, uint32_t notify, int pcnt, const char **paths, DMRESULT_CB cb, void *data);
uint32_t rpc_recursive_param_notify_async(DMCONTEXT *ctx, uint32_t notify, const char *path, DMRESULT_CB cb, void *data);
uint32_t rpc_get_passive_notifications_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_db_addinstance_async(DMCONTEXT *ctx, const char *path, uint16_t id, DMRESULT_CB cb, void *data);
uint32_t rpc_db_delinstance_async(DMCONTEXT *ctx, const char *path, DMRESULT_CB cb, void *data);
uint32_t rpc_db_set_async(DMCONTEXT *ctx, int pvcnt, struct rpc_db_set_path_value *values, DMRESULT_CB cb, void *data);
uint32_t rpc_db_get_async(DMCONTEXT *ctx, int pcnt, const char **paths, DMRESULT_CB cb, void *data);
uint32_t rpc_db_list_async(DMCONTEXT *ctx, int level, const char *path, DMRESULT_CB cb, void *data);
uint32_t rpc_db_retrieve_enum_async(DMCONTEXT *ctx, const char *path, DMRESULT_CB cb, void *data);
uint32_t rpc_db_dump_async(DMCONTEXT *ctx, const char *path, DMRESULT_CB cb, void *data);
uint32_t rpc_db_save_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_db_commit_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_db_cancel_async(DMCONTEXT *ctx, DMRESULT_CB cb, void *data);
uint32_t rpc_db_findinstance_async(DMCONTEXT *ctx, const char *path, const char *name, const struct dm2_avp *search, DMRESULT_CB cb, void *data);
uint32_t rpc_register_role_async(DMCONTEXT *ctx, const char *role, DMRESULT_CB cb, void *data);
uint32_t rpc_system_restart_async(DMCONTEXT *ctx);
uint32_t rpc_system_shutdown_async(DMCONTEXT *ctx);
uint32_t rpc_firmware_download_async(DMCONTEXT *ctx, const char *address, uint8_t credentialstype, const char *credential,
				     const char *install_target, uint32_t timeframe, uint8_t retry_count,
				     uint32_t retry_interval, uint32_t retry_interval_increment,
				     DMRESULT_CB cb, void *data);
uint32_t rpc_firmware_commit_async(DMCONTEXT *ctx, int32_t job_id, DMRESULT_CB cb, void *data);
uint32_t rpc_set_boot_order_async(DMCONTEXT *ctx, int pcnt, const char **boot_order, DMRESULT_CB cb, void *data);

/* sync call wrapper's */

uint32_t rpc_startsession(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DM2_AVPGRP *grp);
uint32_t rpc_switchsession(DMCONTEXT *ctx, uint32_t flags, int32_t timeout, DM2_AVPGRP *grp);
uint32_t rpc_endsession(DMCONTEXT *ctx);
uint32_t rpc_sessioninfo(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_cfgsessioninfo(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_subscribe_notify(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_unsubscribe_notify(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_param_notify(DMCONTEXT *ctx, uint32_t notify, int pcnt, const char **paths, DM2_AVPGRP *grp);
uint32_t rpc_recursive_param_notify(DMCONTEXT *ctx, uint32_t notify, const char *path, DM2_AVPGRP *grp);
uint32_t rpc_get_passive_notifications(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_db_addinstance(DMCONTEXT *ctx, const char *path, uint16_t id, DM2_AVPGRP *grp);
uint32_t rpc_db_delinstance(DMCONTEXT *ctx, const char *path, DM2_AVPGRP *grp);
uint32_t rpc_db_set(DMCONTEXT *ctx, int pvcnt, struct rpc_db_set_path_value *values, DM2_AVPGRP *grp);
uint32_t rpc_db_get(DMCONTEXT *ctx, int pcnt, const char **paths, DM2_AVPGRP *grp);
uint32_t rpc_db_list(DMCONTEXT *ctx, int level, const char *path, DM2_AVPGRP *grp);
uint32_t rpc_db_retrieve_enum(DMCONTEXT *ctx, const char *path, DM2_AVPGRP *grp);
uint32_t rpc_db_dump(DMCONTEXT *ctx, const char *path, DM2_AVPGRP *grp);
uint32_t rpc_db_save(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_db_commit(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_db_cancel(DMCONTEXT *ctx, DM2_AVPGRP *grp);
uint32_t rpc_db_findinstance(DMCONTEXT *ctx, const char *path, const char *name, const struct dm2_avp *search, DM2_AVPGRP *grp);
uint32_t rpc_register_role(DMCONTEXT *ctx, const char *role);
uint32_t rpc_system_restart(DMCONTEXT *ctx);
uint32_t rpc_system_shutdown(DMCONTEXT *ctx);
uint32_t rpc_firmware_download(DMCONTEXT *ctx, const char *address, uint8_t credentialstype, const char *credential,
			       const char *install_target, uint32_t timeframe, uint8_t retry_count,
			       uint32_t retry_interval, uint32_t retry_interval_increment,
			       DM2_AVPGRP *grp);
uint32_t rpc_firmware_commit(DMCONTEXT *ctx, int32_t job_id);
uint32_t rpc_set_boot_order(DMCONTEXT *ctx, int pcnt, const char **boot_order);

#endif
