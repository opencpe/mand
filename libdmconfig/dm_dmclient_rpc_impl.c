/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mand/dm_token.h"

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dm_dmclient_rpc_skel.h"

uint32_t rpc_client_active_notify(void *ctx, DM2_AVPGRP *obj) __attribute__ ((weak, alias ("__rpc_client_active_notify")));
uint32_t rpc_client_event_broadcast(void *ctx, const char *path, uint32_t type) __attribute__ ((weak, alias ("__rpc_client_event_broadcast")));

uint32_t __rpc_client_active_notify(void *ctx __attribute__((unused)), DM2_AVPGRP *obj __attribute__((unused)))
{
	return RC_OK;
}

uint32_t __rpc_client_event_broadcast(void *ctx __attribute__((unused)), const char *path __attribute__((unused)), uint32_t type __attribute__((unused)))
{
	return RC_OK;
}
