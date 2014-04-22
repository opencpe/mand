/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * dmconfig library
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/queue.h>

#ifdef LIBDMCONFIG_DEBUG
#include "debug.h"
#endif

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "mand/dm_token.h"
#include "mand/dm_strings.h"

#include "dmmsg.h"
#include "codes.h"
#include "dmconfig.h"

#include "utils/logx.h"
#include "utils/binary.h"

int dmconfig_debug_level = 1;

/** @defgroup API API
 *  This is the user visible API
 */

#define debug(format, ...)						\
	do {								\
		struct timeval tv;					\
		int _errno = errno;					\
									\
		gettimeofday(&tv, NULL);				\
		logx(LOG_DEBUG, "%ld.%06ld: %s" format, tv.tv_sec, tv.tv_usec, __FUNCTION__, ## __VA_ARGS__); \
		errno = _errno;						\
	} while (0)


/** converts an arbitrary typed AVP data to an ASCII string
 *
 * @param [in] type       Type of AVP to decode
 * @param [in] data       Pointer to date to decode
 * @param [in] len        Length of value
 * @param [inout] val     Pointer to pointer to store the result in
 *
 * @retval RC_OK                Request was successfull
 * @retval RC_ERR_ALLOC         Out of memory
 *
 * @ingroup API
 */
uint32_t
dm_decode_unknown_as_string(uint32_t type, void *data, size_t len, char **val)
{
	switch (type) {
	case AVP_BOOL:
		return (*val = strdup(dm_get_uint8_avp(data) ? "1" : "0"))
							? RC_OK : RC_ERR_ALLOC;
	case AVP_ENUMID:
	case AVP_INT32:
		return asprintf(val, "%d", dm_get_int32_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_COUNTER:
	case AVP_UINT32:
		return asprintf(val, "%u", dm_get_uint32_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_ABSTICKS:
	case AVP_RELTICKS:
	case AVP_INT64:
		return asprintf(val, "%" PRIi64, dm_get_int64_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_UINT64:
		return asprintf(val, "%" PRIu64, dm_get_uint64_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_ENUM:
	case AVP_PATH:
	case AVP_STRING:
		return (*val = strndup(data, len)) ? RC_OK : RC_ERR_ALLOC;
	case AVP_BINARY: {
		*val = malloc(((len + 3) * 4) / 3);
		if (!*val)
			return RC_ERR_ALLOC;

		dm_to64(data, len, *val);
		return RC_OK;
	}
	case AVP_ADDRESS: {
		char buf[INET6_ADDRSTRLEN];
		int af;
		union {
			struct in_addr	in;
			struct in6_addr	in6;
		} addr;

		if (!dm_get_address_avp(&af, &addr, sizeof(addr), data, len))
			return RC_ERR_MISC;
		inet_ntop(af, &addr, buf, sizeof(buf));
		return (*val = strdup(buf)) ? RC_OK : RC_ERR_ALLOC;
	}
	case AVP_DATE:
		return asprintf(val, "%u", (uint32_t)dm_get_time_avp(data)) == -1
							? RC_ERR_ALLOC : RC_OK;
	case AVP_TYPE:
		switch (dm_get_uint32_avp(data)) {
		case AVP_TABLE:
			return (*val = strdup("<<table>>")) ? RC_OK : RC_ERR_ALLOC;
		case AVP_OBJECT:
			return (*val = strdup("<<object>>")) ? RC_OK : RC_ERR_ALLOC;
		case AVP_INSTANCE:
			return (*val = strdup("<<instance>>")) ? RC_OK : RC_ERR_ALLOC;
		}
		return RC_ERR_MISC;

	default:
		return RC_ERR_MISC;
	}

	/* never reached */
}

/* API v2 */

uint32_t dm_expect_end(DM2_AVPGRP *grp)
{
	return dm_expect_group_end(grp);
}

uint32_t dm_expect_raw(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, void **data, size_t *size)
{
	uint32_t code;
	uint32_t vendor_id;

	assert(grp != NULL);
	assert(data != NULL);
	assert(size != NULL);

	if (dm_expect_avp(grp, &code, &vendor_id, data, size) != RC_OK
	    || code != exp_code
	    || vendor_id != exp_vendor_id)
		return RC_ERR_MISC;

	return RC_OK;
}

uint32_t dm_expect_value(DM2_AVPGRP *grp, struct dm2_avp *avp)
{
	assert(grp != NULL);
	assert(avp != NULL);

	return dm_expect_avp(grp, &avp->code, &avp->vendor_id, &avp->data, &avp->size);
}

uint32_t dm_expect_object(DM2_AVPGRP *grp, DM2_AVPGRP *obj)
{
	assert(grp != NULL);
	assert(obj != NULL);

	return dm_expect_group(grp, AVP_CONTAINER, VP_TRAVELPING, obj);
}


uint32_t dm_expect_bin(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, struct dm_bin *bin)
{
	assert(grp != NULL);
	assert(bin != NULL);

	return dm_expect_raw(grp, exp_code, exp_vendor_id, &bin->data, &bin->size);
}

uint32_t dm_expect_string_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, char **value)
{
	size_t size;
	void *data;
	uint32_t r;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size)) != RC_OK)
		return r;

	if (!(*value = talloc_strndup(grp->ctx, data, size)))
		return RC_ERR_ALLOC;

	return RC_OK;
}

uint32_t dm_expect_uint8_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint8_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_uint8_avp(data);
	return RC_OK;
}

uint32_t dm_expect_uint16_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint16_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_uint16_avp(data);
	return RC_OK;
}

uint32_t dm_expect_uint32_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint32_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_uint32_avp(data);
	return RC_OK;
}

uint32_t dm_expect_uint64_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint64_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_uint64_avp(data);
	return RC_OK;
}

uint32_t dm_expect_int8_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int8_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_int8_avp(data);
	return RC_OK;
}

uint32_t dm_expect_int16_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int16_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_int16_avp(data);
	return RC_OK;
}

uint32_t dm_expect_int32_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int32_t *value)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);
	assert(value != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK)
	    || size != sizeof(*value))
		return RC_ERR_MISC;

	*value = dm_get_int32_avp(data);
	return RC_OK;
}

uint32_t dm_expect_address_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int *af, struct in_addr *addr, size_t addr_size)
{
	uint32_t r;
	size_t size;
	void *data;

	assert(grp != NULL);

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size) != RC_OK))
		return RC_ERR_MISC;

	dm_get_address_avp(af, addr, addr_size, data, size);
	return RC_OK;
}

uint32_t
dm_expect_group(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, DM2_AVPGRP *obj)
{
	uint32_t r;
	void *data;
	size_t size;

	if ((r = dm_expect_raw(grp, exp_code, exp_vendor_id, &data, &size)) != RC_OK)
		return r;

	dm_init_avpgrp(grp->ctx, data, size, obj);
	return RC_OK;
}

uint32_t
dm_expect_group_end(DM2_AVPGRP *grp)
{
	if (grp->pos == grp->size)
		return RC_OK;

	return RC_ERR_AVP_MISFORMED;
}


/* request handling */

DM2_REQUEST *dm_new_request(void *ctx, uint32_t code, uint8_t flags, uint32_t hopid, uint32_t endid)
{
	DM2_REQUEST *req;

	if (!(req = talloc_zero(ctx, DM2_REQUEST)))
		return NULL;

	if (dm_new_packet(ctx, req, code, flags, APP_ID, hopid, endid) != RC_OK) {
		talloc_free(req);
		return NULL;
	}

	return req;
}
