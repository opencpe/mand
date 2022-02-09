/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the client for the server
 *
 * prototypes for the server implementation
 */

#ifndef DM_DMCLIENT_RPC_IMPL_H
#define DM_DMCLIENT_RPC_IMPL_H

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dm_dmclient_rpc_skel.h"

uint32_t rpc_client_active_notify(void *ctx, DM2_AVPGRP *obj);
uint32_t rpc_client_event_broadcast(void *ctx, const char *path, uint32_t type);
uint32_t rpc_agent_firmware_download(void *ctx, char *address, uint8_t credentialstype, char *credential,
				     char *install_target, uint32_t timeframe, uint8_t retry_count,
				     uint32_t retry_interval, uint32_t retry_interval_increment,
				     DM2_REQUEST *answer);
uint32_t rpc_agent_firmware_commit(void *ctx, int32_t job_id);
uint32_t rpc_agent_set_boot_order(void *ctx, int pcnt, const char **boot_order);

#endif
