/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * functions to build AVP group and request objects
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "errors.h"
#include "codes.h"
#include "dmmsg.h"

int
dm_get_address_avp(int *af, void *addr, socklen_t size, const void *src, size_t len) {
	if(*(uint16_t *)src == htons(IANA_INET)) {
		if (len < sizeof(struct in_addr) + 2 || size < sizeof(struct in_addr))
			return 1;
		*af = AF_INET;
		*(struct in_addr *)addr = *(struct in_addr *)(((uint8_t *)src) + 2);
		return sizeof(struct in_addr);
	} else if(*(uint16_t *)src == htons(IANA_INET6)) {
		if (len < sizeof(struct in6_addr) + 2 || size < sizeof(struct in6_addr))
			return 1;
		*af = AF_INET6;
		*(struct in6_addr *)addr = *(struct in6_addr *)(((uint8_t *)src) + 2);
		return sizeof(struct in6_addr);
	} else
		return 0;
}

/* API v2 */

/* decoder functions */

void
dm_init_packet(DM_PACKET *packet, DM2_AVPGRP *grp)
{
	dm_init_avpgrp(packet, packet + 1, dm_packet_length(packet) - sizeof(struct dm_packet), grp);
}

void
dm_init_avpgrp(void *ctx, void *data, size_t size, DM2_AVPGRP *grp)
{
	assert(data != NULL);
	assert(grp != NULL);

	grp->ctx = ctx;
	grp->data = data;
	grp->size = size;
	grp->pos = 0;
}

uint32_t
dm_copy_avpgrp(DM2_AVPGRP *dest, DM2_AVPGRP *src)
{
	assert(dest);
	assert(src);

	if (!(dest->data = talloc_memdup(dest->ctx, src->data, src->size)))
	      return RC_ERR_ALLOC;

	dest->size = src->size;
	dest->pos = src->pos;

	return RC_OK;
}

uint32_t
dm_expect_avp(DM2_AVPGRP *grp, uint32_t *code, uint32_t *vendor_id, void **data, size_t *len)
{
	struct dm_avp *avp;
	size_t avp_len, padded_avp_len;

	assert(grp != NULL);
	assert(code != NULL);
	assert(vendor_id != NULL);
	assert(data != NULL);
	assert(len != NULL);

	if (grp->pos >= grp->size)
		return RC_ERR_AVP_END;

	avp = (struct dm_avp *)(grp->data + grp->pos);
	avp_len = uint24to32(avp->length);
	padded_avp_len = PAD32(avp_len);

	if (avp_len < 8
	    || ((avp->flags & AVP_FLAG_VENDOR) != 0 && avp_len < 12)
	    || grp->pos + padded_avp_len > grp->size)
		return RC_ERR_INVALID_AVP_LENGTH;

	grp->pos += padded_avp_len;

	*code = ntohl(avp->code);
	*vendor_id = 0;
	*len = avp_len - 8;
	*data = ((uint8_t*)avp) + 8;

	if (avp->flags & AVP_FLAG_VENDOR) {
		*vendor_id = ntohl(avp->vendor_id);
		*len -= 4;
		*data += 4;
	}

	return RC_OK;
}

/* encoder functions */

uint32_t
dm_new_packet(void *ctx, DM2_REQUEST *req, uint32_t code, uint8_t flags, uint32_t appid, uint32_t hopid, uint32_t endid)
{
	DM_PACKET *pkt;

	assert(req != NULL);

	memset(req, 0, sizeof(DM2_REQUEST));

	if (!(req->packet = pkt = talloc_zero_size(ctx, DM_BLOCK_ALLOC)))
		return RC_ERR_ALLOC;

	pkt->version = 1;
	uint32to24(pkt->code, code);
	pkt->flags = flags;
	uint32to24(pkt->length, sizeof(struct dm_packet));
	pkt->app_id = htonl(appid);
	pkt->hop2hop_id = htonl(hopid);
	pkt->end2end_id = htonl(endid);

	req->grp[0].start = req->grp[0].pos = sizeof(struct dm_packet);

	return RC_OK;
}

uint32_t
dm_finalize_packet(DM2_REQUEST *req)
{
	if (req->level != 0)
		return RC_ERR_AVP_MISFORMED;

	uint32to24(req->packet->length, req->grp[0].pos);

	return RC_OK;
}

uint32_t
dm_new_group(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id)
{
	req->grp[req->level + 1].start = req->grp[req->level + 1].pos = req->grp[req->level].pos;
	req->level++;

	return dm_put_avp(req, code, vendor_id, NULL, 0);
}

uint32_t
dm_finalize_group(DM2_REQUEST *req)
{
	struct dm_avp *avp;
	size_t avp_len;

	if (req->level == 0)
		return RC_ERR_AVP_MISFORMED;

	avp = (struct dm_avp *)(((unsigned char *)req->packet) + req->grp[req->level].start);
	avp_len = req->grp[req->level].pos - req->grp[req->level].start;
	uint32to24(avp->length, avp_len);

	req->level--;

	req->grp[req->level].pos += PAD32(avp_len);
	return RC_OK;
}

static uint32_t
dm_packet_ensure_space(DM2_REQUEST *req, size_t len)
{
	size_t have = ((req->grp[req->level].pos + DM_BLOCK_ALLOC - 1) % DM_BLOCK_ALLOC);
	size_t want = ((req->grp[req->level].pos + DM_BLOCK_ALLOC - 1 + len) % DM_BLOCK_ALLOC);

	if (have == want)
		return RC_OK;

	if (!(req->packet = talloc_realloc_size(NULL, req->packet, want * DM_BLOCK_ALLOC)))
		return RC_ERR_ALLOC;

	return RC_OK;
}

uint32_t dm_add_uint32_get_pos(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint32_t value, size_t *pos)
{
	assert(pos != NULL);

	*pos = req->grp[req->level].pos + 8;
	if (vendor_id != 0)
		*pos += 4;

	return dm_add_uint32(req, code, vendor_id, value);
}

void dm_put_uint32_at_pos(DM2_REQUEST *req, size_t pos, uint32_t value)
{
	*(uint32_t *)(((unsigned char *)req->packet) + pos) = htonl(value);
}

uint32_t
dm_put_avp(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, const void *data, size_t len)
{
	uint32_t rc;
	struct dm_avp *avp;
	size_t avp_len = len + 8;
	void *d;

	if (len != 0 && !data)
		return RC_ERR_AVP_MISFORMED;

	if ((rc = dm_packet_ensure_space(req, len + 12)) != RC_OK)
		return rc;

	d = avp = (struct dm_avp *)(((unsigned char *)req->packet) + req->grp[req->level].pos);
	d += 8;

	avp->code = htonl(code);
	if (vendor_id != 0) {
		avp->flags |= AVP_FLAG_VENDOR;
		avp->vendor_id = htonl(vendor_id);
		avp_len += 4;
		d += 4;
	}

	if (data)
		memcpy(d, data, len);
	uint32to24(avp->length, avp_len);

	req->grp[req->level].pos += PAD32(avp_len);
	return RC_OK;
}

uint32_t
dm_add_address(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int af, const void *data)
{
	struct __attribute__ ((__packed__)) {
		uint16_t af;
		union {
			struct in_addr	in;
			struct in6_addr	in6;
		};
	} addr;

	if(af == AF_INET) {
		addr.af = htons(IANA_INET);
		addr.in = *(struct in_addr *)data;
		return dm_put_avp(req, code, vendor_id, &addr, sizeof(struct in_addr) + 2);
	} else if(af == AF_INET6) {
		addr.af = htons(IANA_INET6);
		addr.in6 = *(struct in6_addr *)data;
		return dm_put_avp(req, code, vendor_id, &addr, sizeof(struct in6_addr) + 2);
	} else
		return RC_ERR_INVALID_AVP_TYPE;
}

