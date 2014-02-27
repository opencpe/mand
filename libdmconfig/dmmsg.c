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
get_avp(uint32_t *code, uint8_t *flags, uint32_t *vendor_id,
	void **data, size_t *len, DM_AVP **avp) {
	int avp_len;

	if((avp_len = dm_avp_length(*avp)) < 8)
		return DM_INVALID_AVP_LENGTH;

	if((*avp)->flags & AVP_FLAG_RESERVED)
		return DM_INVALID_AVP_BITS;

	*code = ntohl((*avp)->code);
	*flags = (*avp)->flags & (AVP_FLAG_MANDATORY | AVP_FLAG_PRIVAT);
	*len = avp_len - 8;
	*data = (uint8_t*)*avp + 8;

	if((*avp)->flags & AVP_FLAG_VENDOR) {
		if(avp_len < 12)
			return DM_INVALID_AVP_LENGTH;
		*vendor_id = ntohl((*avp)->vendor_id);
		*len -= 4;
		*data += 4;
	}
	*(uint8_t**)avp += PAD32(avp_len);

	return 0;
}

DM_REQUEST *
new_dm_request(void *ctx, uint32_t code, uint8_t flags,
		 uint32_t appid, uint32_t hopid, uint32_t endid) {
	DM_REQUEST *req;

	if(!(req = talloc_zero(ctx, DM_REQUEST)))
		return NULL;

	req->info.size = sizeof(DM_REQUEST);

	req->packet.version = 1;
	uint32to24(req->packet.code, code);
	req->packet.flags = flags;
	req->packet.app_id = htonl(appid);
	req->packet.hop2hop_id = htonl(hopid);
	req->packet.end2end_id = htonl(endid);

	return req;
}

/**
 * start decoding a request received from the network
 * minimum lenght of received data if 4 bytes
 *
 * @param ctx     talloc memory context for request
 * @param req     pointer to pointer to new request structure
 * @param data    pointer to the data read from the network
 * @param len     length of data
 *
 * @result        amount of data read form buffer
 */
int
dm_decode_request(void *ctx, DM_REQUEST **req, void *data, size_t len) {
	size_t pkt_len;
	DM_PACKET *pkt = (DM_PACKET *)data;

	assert(req != NULL);
	if (len < 4)
		return 0;

	pkt_len = dm_packet_length(pkt);
	if (len > pkt_len)
		len = pkt_len;

	if(!(*req = talloc_size(ctx, sizeof(DM_REQUEST_INFO) + dm_packet_length(pkt))))
		return 0;

	(*req)->info.size = sizeof(DM_REQUEST_INFO) + dm_packet_length(pkt);
	(*req)->info.avpptr = (DM_AVP*)((uint8_t*)(*req) + sizeof(DM_REQUEST) + len);
	memcpy(&(*req)->packet, data, len);

	return len;
}

int
dm_add_data(DM_REQUEST *req, void *data, size_t len) {
	size_t remaining;
	size_t current;

	current = (uint8_t *)req + req->info.size - (uint8_t *)req->info.avpptr;
	remaining = dm_packet_length(&req->packet) - current;

	if (remaining < len)
		len = remaining;

	memcpy(req->info.avpptr, data, len);
	req->info.avpptr = (DM_AVP*)((uint8_t *)req->info.avpptr + len);

	return len;
}

int
dm_decode_complete(DM_REQUEST *req) {
	size_t remaining;
	size_t current;

	current = (uint8_t *)req + req->info.size - (uint8_t *)req->info.avpptr;
	remaining = dm_packet_length(&req->packet) - current;

	return (remaining == 0);
}

int
build_dm_request(void *ctx, DM_REQUEST **req, DM_AVPGRP *avpgrp) {
	if(avpgrp) {
		(*req)->info.size += avpgrp->info.avps_length;
		if(!(*req = talloc_realloc_size(ctx, *req, (*req)->info.size)))
			return 1;
		(*req)->info.avpptr = (DM_AVP*)((uint8_t*)*req + sizeof(DM_REQUEST));

		uint32to24((*req)->packet.length, sizeof(DM_PACKET) + avpgrp->info.avps_length);
		memcpy((*req)->info.avpptr, (uint8_t*)avpgrp + sizeof(DM_AVPGRP), avpgrp->info.avps_length);
	} else {
		uint32to24((*req)->packet.length, sizeof(DM_PACKET));
		(*req)->info.avpptr = (DM_AVP*)((uint8_t*)*req + sizeof(DM_REQUEST));
	}

	return 0;
}

DM_AVPGRP *
new_dm_avpgrp(void *ctx) {
	DM_AVPGRP *avpgrp;

	if(!(avpgrp = talloc_size(ctx, DM_BLOCK_ALLOC)))
		return NULL;

	avpgrp->info.avpptr = NULL;
	avpgrp->info.avps_length = 0;
	avpgrp->info.size = DM_BLOCK_ALLOC;

	return avpgrp;
}

DM_AVPGRP *
dm_decode_avpgrp(void *ctx, void *data, size_t len) {
	DM_AVPGRP *avpgrp;

	if(!(avpgrp = talloc_size(ctx, sizeof(DM_AVPGRP) + len)))
		return NULL;

	avpgrp->info.avpptr = (DM_AVP*)((uint8_t*)avpgrp + sizeof(DM_AVPGRP));
	avpgrp->info.size = sizeof(DM_AVPGRP) + len;
	avpgrp->info.avps_length = len;
	memcpy(avpgrp->info.avpptr, data, len);

	return avpgrp;
}

int
dm_avpgrp_add_avpgrp(void *ctx, DM_AVPGRP **avpgrp,
		       uint32_t code, uint8_t flags, uint32_t vendor_id,
		       DM_AVPGRP *source) {
	if(!(flags & AVP_FLAG_MANDATORY)) {
		uint8_t	*avp = (uint8_t*)source + sizeof(DM_AVPGRP);
		uint8_t	*last = (uint8_t*)avp + source->info.avps_length;

		for(; avp < last; avp += PAD32(dm_avp_length((DM_AVP*)avp)))
			if(((DM_AVP*)avp)->flags & AVP_FLAG_MANDATORY)
				return 1;
	}

	return dm_avpgrp_add_raw(ctx, avpgrp, code, flags, vendor_id,
				   (uint8_t*)source + sizeof(DM_AVPGRP), source->info.avps_length);
}

int
dm_avpgrp_insert_raw(void *ctx, DM_AVPGRP **avpgrp, const void *data, size_t len) {
	uint32_t new_size;

	if((new_size = sizeof(DM_AVPGRP) + (*avpgrp)->info.avps_length + len) > (*avpgrp)->info.size) {
		(*avpgrp)->info.size = (new_size/DM_BLOCK_ALLOC + 1) * DM_BLOCK_ALLOC;
		if(!(*avpgrp = talloc_realloc_size(ctx, *avpgrp, (*avpgrp)->info.size)))
			return 1;
	}

	memcpy((uint8_t*)*avpgrp + sizeof(DM_AVPGRP) + (*avpgrp)->info.avps_length, data, len);
	(*avpgrp)->info.avps_length += len;

	return 0;
}

int
dm_avpgrp_add_raw(void *ctx, DM_AVPGRP **avpgrp,
		    uint32_t code, uint8_t flags, uint32_t vendor_id,
		    const void *data, size_t len) {
	DM_AVP	*avp;
	uint8_t		*payload;
	int		avp_len;
	uint32_t	new_size;

	if((new_size = sizeof(DM_AVPGRP) + (*avpgrp)->info.avps_length +
			sizeof(DM_AVP) + PAD32(len)) > (*avpgrp)->info.size) {
		(*avpgrp)->info.size = (new_size/DM_BLOCK_ALLOC + 1) * DM_BLOCK_ALLOC;
		if(!(*avpgrp = talloc_realloc_size(ctx, *avpgrp, (*avpgrp)->info.size)))
			return 1;
	}

	avp = (DM_AVP*)((uint8_t*)*avpgrp + sizeof(DM_AVPGRP) + (*avpgrp)->info.avps_length);
	payload = (uint8_t*) avp + 8;
	avp_len = len + 8;

	avp->code = htonl(code);
	avp->flags = flags & (AVP_FLAG_MANDATORY | AVP_FLAG_PRIVAT);
	if(vendor_id) {
		avp->flags |= AVP_FLAG_VENDOR;
		avp->vendor_id = htonl(vendor_id);
		payload += 4;
		avp_len += 4;
	}

	uint32to24(avp->length, avp_len);
	memcpy(payload, data, len);

	memset(payload + len, 0, PAD32(avp_len) - avp_len);
	(*avpgrp)->info.avps_length += PAD32(avp_len);

	return 0;
}

int
dm_avpgrp_add_address(void *ctx, DM_AVPGRP **avpgrp,
			uint32_t code, uint8_t flags, uint32_t vendor_id,
			int af, const void *data) {
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
		return dm_avpgrp_add_raw(ctx, avpgrp, code, flags, vendor_id, &addr, sizeof(struct in_addr) + 2);
	} else if(af == AF_INET6) {
		addr.af = htons(IANA_INET6);
		addr.in6 = *(struct in6_addr *)data;
		return dm_avpgrp_add_raw(ctx, avpgrp, code, flags, vendor_id, &addr, sizeof(struct in6_addr) + 2);
	} else
		return 1;
}

int
dm_avpgrp_add_uint32_string(void *ctx, DM_AVPGRP **avpgrp, uint32_t code,
			      uint8_t flags, uint32_t vendor_id, uint32_t d1, const char *d2) {
	uint8_t	*buf;
	int	size, rc;

	if(!(buf = malloc(size = strlen(d2) + sizeof(uint32_t))))
		return 1;

	*(uint32_t*)buf = htonl(d1);
	memcpy(buf + sizeof(uint32_t), d2, size - sizeof(uint32_t));

	rc = dm_avpgrp_add_raw(ctx, avpgrp,code, flags, vendor_id, buf, size);
	free(buf);
	return rc;
}

int
dm_get_address_avp(int *af, void *addr, const void *src) {
	if(*(uint16_t *)src == htons(IANA_INET)) {
		*af = AF_INET;
		*(struct in_addr *)addr = *(struct in_addr *)(((uint8_t *)src) + 2);
		return sizeof(struct in_addr);
	} else if(*(uint16_t *)src == htons(IANA_INET6)) {
		*af = AF_INET6;
		*(struct in6_addr *)addr = *(struct in6_addr *)(((uint8_t *)src) + 2);
		return sizeof(struct in6_addr);
	} else
		return 0;
}

