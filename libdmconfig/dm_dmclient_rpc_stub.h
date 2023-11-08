/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the server to the client
 *
 * prototypes for server stub's
 */

#ifndef DM_DMCLIENT_RPC_STUB_H
#define DM_DMCLIENT_RPC_STUB_H

#include "libdmconfig/dmcontext.h"

#include "mand/dm_token.h"
#include "mand/dm_notify.h"

uint32_t rpc_event_broadcast(DMCONTEXT *ctx, const char *path, uint32_t type);
uint32_t rpc_agent_firmware_download_async(DMCONTEXT *ctx, const char *address, uint8_t credentialstype, const char *credential,
					   const char *install_target, uint32_t timeframe, uint8_t retry_count,
					   uint32_t retry_interval, uint32_t retry_interval_increment,
					   DMRESULT_CB cb, void *data);
uint32_t rpc_agent_firmware_commit_async(DMCONTEXT *ctx, int32_t job_id, DMRESULT_CB cb, void *data);
uint32_t rpc_agent_set_boot_order_async(DMCONTEXT *ctx, int pcnt, const char **boot_order, DMRESULT_CB cb, void *data);

#endif
