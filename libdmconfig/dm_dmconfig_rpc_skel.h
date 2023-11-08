/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the client for the server
 *
 * prototypes for the main request handler switch
 */

#ifndef DM_DMCONFIG_RPC_SKEL_H
#define DM_DMCONFIG_RPC_SKEL_H

#include <stdlib.h>

//#include "mand/dm_dmconfig.h"

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"

struct dm_request_info {
	/** SOCKCONTEXT on which the request was received */
	void *ctx;
	/** partially prepared answer */
	DM2_REQUEST *answer;
	/** position of return code in answer */
	size_t rc_pos;
};

uint32_t rpc_dmconfig_switch(void *ctx, const DMC_REQUEST *req, DM2_AVPGRP *obj,
                             struct dm_request_info *request_info);

#endif
