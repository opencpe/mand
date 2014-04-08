/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/** RPC's from the server for the client
 *
 * the main request handler switch and the argument demarshaling
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm_dmclient_rpc_skel.h"
#include "dm_dmclient_rpc_impl.h"

#ifdef LIBDMCONFIG_DEBUG
#include "libdmconfig/debug.h"
#endif

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "libdmconfig/dmmsg.h"
#include "libdmconfig/dmconfig.h"
#include "libdmconfig/dmcontext.h"
#include "libdmconfig/codes.h"

uint32_t
rpc_dmclient_switch(void *ctx, const DMC_REQUEST *req, DM2_AVPGRP *obj __attribute__((unused)), DM2_REQUEST **answer)
{
	uint32_t rc;
	size_t pos;

	/* one way requests */
	switch (req->code) {
	}

	if (!(*answer = dm_new_request(ctx, req->code, 0, req->hop2hop, req->end2end)))
		return RC_ERR_ALLOC;

	/* make the RC the first AVP and remember it's position */
	if ((rc = dm_add_uint32_get_pos(*answer, AVP_RC, VP_TRAVELPING, RC_OK, &pos)) != RC_OK)
		return rc;

	switch (req->code) {
	default:
		rc = RC_ERR_CONNECTION;
		break;
	}

	if (rc != RC_ERR_ALLOC) {
		/* fill in the RC */
		dm_put_uint32_at_pos(*answer, pos, rc);
		return dm_finalize_packet(*answer);
	}

	return rc;
}
