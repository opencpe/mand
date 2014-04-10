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

static inline uint32_t
rpc_client_active_notify_skel(void *ctx, DM2_AVPGRP *obj)
{
	return rpc_client_active_notify(ctx, obj);
}

static inline uint32_t
rpc_client_event_broadcast_skel(void *ctx, DM2_AVPGRP *obj)
{
	uint32_t rc;
	char *path;
	uint32_t type;

	if ((rc = dm_expect_string_type(obj, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK
	    || (rc = dm_expect_uint32_type(obj, AVP_EVENT_TYPE, VP_TRAVELPING, &type)) != RC_OK
	    || (rc = dm_expect_end(obj)) != RC_OK)
		return rc;

	return rpc_client_event_broadcast(ctx, path, type);
}

static inline uint32_t
rpc_client_get_interface_state_skel(void *ctx, DM2_AVPGRP *obj, DM2_REQUEST *answer)
{
        uint32_t rc;
	char *if_name;

        if ((rc = dm_expect_string_type(obj, AVP_STRING, VP_TRAVELPING, &if_name)) != RC_OK
            || (rc = dm_expect_end(obj)) != RC_OK)
                return rc;

        return rpc_client_get_interface_state(ctx, if_name, answer);
}


uint32_t
rpc_dmclient_switch(void *ctx, const DMC_REQUEST *req, DM2_AVPGRP *obj __attribute__((unused)), DM2_REQUEST **answer)
{
	uint32_t rc;
	size_t pos;

	/* one way requests */
	switch (req->code) {
	case CMD_CLIENT_ACTIVE_NOTIFY:
		return rpc_client_active_notify_skel(ctx, obj);
	case CMD_CLIENT_EVENT_BROADCAST:
		return rpc_client_event_broadcast_skel(ctx, obj);
	}

	if (!(*answer = dm_new_request(ctx, req->code, 0, req->hop2hop, req->end2end)))
		return RC_ERR_ALLOC;

	/* make the RC the first AVP and remember it's position */
	if ((rc = dm_add_uint32_get_pos(*answer, AVP_RC, VP_TRAVELPING, RC_OK, &pos)) != RC_OK)
		return rc;

	switch (req->code) {
	case CMD_CLIENT_GET_INTERFACE_STATE:
		rc = rpc_client_get_interface_state_skel(ctx, obj, *answer);
                break;

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
