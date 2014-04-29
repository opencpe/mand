/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mand/dm_token.h"

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dm_dmclient_rpc_skel.h"

uint32_t rpc_client_active_notify(void *ctx, DM2_AVPGRP *obj) __attribute__ ((weak, alias ("__rpc_client_active_notify")));
uint32_t rpc_client_event_broadcast(void *ctx, const char *path, uint32_t type) __attribute__ ((weak, alias ("__rpc_client_event_broadcast")));
uint32_t rpc_client_get_interface_state(void *ctx, const char *if_name, DM2_REQUEST *answer) __attribute__ ((weak, alias ("__rpc_client_get_interface_state")));
uint32_t rpc_agent_firmware_download(void *ctx, char *address, uint8_t credentialstype, char *credential,
				     char *install_target, uint32_t timeframe, uint8_t retry_count,
				     uint32_t retry_interval, uint32_t retry_interval_increment,
				     DM2_REQUEST *answer) __attribute__ ((weak, alias ("__rpc_agent_firmware_download")));
uint32_t rpc_agent_firmware_commit(void *ctx, int32_t job_id) __attribute__ ((weak, alias ("__rpc_agent_firmware_commit")));
uint32_t rpc_agent_set_boot_order(void *ctx, int pcnt, const char **boot_order) __attribute__ ((weak, alias ("__rpc_agent_set_boot_order")));

uint32_t __rpc_client_active_notify(void *ctx __attribute__((unused)), DM2_AVPGRP *obj __attribute__((unused)))
{
	return RC_OK;
}

uint32_t __rpc_client_event_broadcast(void *ctx __attribute__((unused)), const char *path __attribute__((unused)), uint32_t type __attribute__((unused)))
{
	return RC_OK;
}

uint32_t __rpc_client_get_interface_state(void *ctx __attribute__((unused)), const char *if_name __attribute__((unused)), DM2_REQUEST *answer __attribute__((unused)))
{
	return RC_OK;
}

uint32_t __rpc_agent_firmware_download(void *ctx __attribute__((unused)),
				       char *address __attribute__((unused)),
				       uint8_t credentialstype __attribute__((unused)),
				       char *credential __attribute__((unused)),
				       char *install_target __attribute__((unused)),
				       uint32_t timeframe __attribute__((unused)),
				       uint8_t retry_count __attribute__((unused)),
				       uint32_t retry_interval __attribute__((unused)),
				       uint32_t retry_interval_increment __attribute__((unused)),
				       DM2_REQUEST *answer __attribute__((unused)))
{
	return RC_OK;
}


uint32_t __rpc_agent_firmware_commit(void *ctx __attribute__((unused)), int32_t job_id __attribute__((unused)))
{
	return RC_OK;
}

uint32_t __rpc_agent_set_boot_order(void *ctx __attribute__((unused)), int pcnt __attribute__((unused)), const char **boot_order __attribute__((unused)))
{
	return RC_OK;
}
