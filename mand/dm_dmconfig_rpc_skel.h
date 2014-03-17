/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DM_DMCONFIG_RPC_SKEL_H
#define DM_DMCONFIG_RPC_SKEL_H

struct rpc_db_set_path_value {
	dm_selector path;
	struct dm2_avp value;
};

struct path_type {
	uint32_t type;
	dm_selector path;
};

uint32_t rpc_dmconfig_switch(SOCKCONTEXT *sockCtx, const DMC_REQUEST *req, DM2_AVPGRP *obj, DM_OBJ **answer);

#endif
