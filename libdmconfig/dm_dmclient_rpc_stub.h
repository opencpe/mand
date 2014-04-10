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
uint32_t rpc_get_interface_state_async(DMCONTEXT *ctx, const char *if_name, DMRESULT_CB cb, void *data);

uint32_t rpc_get_interface_state(DMCONTEXT *ctx, const char *if_name, DM2_AVPGRP *answer);

#endif
