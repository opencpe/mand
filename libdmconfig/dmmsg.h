/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DMMSG_H
#define __DMMSG_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bits/byteswap.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include "libdmconfig/codes.h"

/* see http://www.iana.org/assignments/address-family-numbers/address-family-numbers.txt */
#define IANA_INET      1
#define IANA_INET6     2

#if __BYTE_ORDER == __BIG_ENDIAN
/* The host byte order is the same as network byte order,
   so these functions are all just identity.  */
#define ntohll(x)		(x)
#define htonll(x)		(x)

#else

#define ntohll(x)		__bswap_64(x)
#define htonll(x)		__bswap_64(x)
#endif

#define DM_BLOCK_ALLOC	2048

#define PAD32(x)		((x + 3) & ~3)

#define TIME_SINCE_EPOCH	2208988800


		/* structures */
typedef struct dm_avp			DM_AVP;
typedef struct dm_packet		DM_PACKET;
typedef struct dm_timeval		DM_TIMEVAL;

struct dm_avp {
	uint32_t	code;
	uint8_t		flags;
	uint8_t		length[3];
	uint32_t	vendor_id;
} __attribute__ ((packed));

struct dm_packet {
	uint8_t		version;
	uint8_t		length[3];
	uint8_t		flags;
	uint8_t		code[3];
	uint32_t	app_id;
	uint32_t	hop2hop_id;
	uint32_t	end2end_id;
	unsigned char   avps[];
} __attribute__ ((packed));

/* Request API v2 */

typedef struct dm2_avpgrp {
	void *ctx;
	void *data;
	size_t size;
	size_t pos;
} DM2_AVPGRP;

typedef struct dm2_request {
	struct {
		size_t start;
		size_t pos;
	} grp[16];
	int level;

	DM_PACKET *packet;
} DM2_REQUEST;

/* timeval structure as transmitted in an AVP_TIMEVAL */
struct dm_timeval {
	uint32_t	tv_sec;		/* maximum size of both fields is 32 bit */
	uint32_t	tv_usec;
} __attribute__ ((packed));

		/* dmconfig packet flag bitmask constants */

#define CMD_FLAG_REQUEST	(1 << 7)
#define CMD_FLAG_PROXIABLE	(1 << 6)
#define CMD_FLAG_ERROR		(1 << 5)
#define CMD_FLAG_RETRANSMITED	(1 << 4)
#define CMD_FLAG_RESERVED	(~(CMD_FLAG_REQUEST | CMD_FLAG_PROXIABLE | CMD_FLAG_ERROR | CMD_FLAG_RETRANSMITED))

		/* dmconfig AVP flag bitmask constants */

#define AVP_FLAG_VENDOR		(1 << 7)
#define AVP_FLAG_MANDATORY	(1 << 6)
#define AVP_FLAG_PRIVAT		(1 << 5)
#define AVP_FLAG_RESERVED	(~(AVP_FLAG_VENDOR | AVP_FLAG_MANDATORY | AVP_FLAG_PRIVAT))

		/* function headers */

int dm_get_address_avp(int *af, void *addr, socklen_t size, const void *src, size_t len);

static inline uint32_t uint24to32(uint8_t i24[3]);
static inline void uint32to24(uint8_t i24[3], uint32_t i32);
static inline uint8_t dm_packet_flags(DM_PACKET *pkt);
static inline uint32_t dm_packet_length(DM_PACKET *pkt);
static inline uint32_t dm_packet_code(DM_PACKET *pkt);
static inline uint32_t dm_app_id(DM_PACKET *pkt);
static inline uint32_t dm_end2end_id(DM_PACKET *pkt);
static inline uint32_t dm_hop2hop_id(DM_PACKET *pkt);
static inline uint32_t dm_avp_length(DM_AVP *avp);


static inline int dm_get_string_avp(char *dest, size_t dlen, const void *src, size_t slen);
static inline int8_t dm_get_int8_avp(const void *src);
static inline uint8_t dm_get_uint8_avp(const void *src);
static inline int16_t dm_get_int16_avp(const void *src);
static inline uint16_t dm_get_uint16_avp(const void *src);
static inline int32_t dm_get_int32_avp(const void *src);
static inline uint32_t dm_get_uint32_avp(const void *src);
static inline int64_t dm_get_int64_avp(const void *src);
static inline uint64_t dm_get_uint64_avp(const void *src);
static inline time_t dm_get_time_avp(const void *src);
static inline struct timeval dm_get_timeval_avp(const void *src);

/* v2 request API */
/*
int dm_init_packet(void *ctx, DM_PACKET **packet, DM2_AVPGRP *grp, void *data, size_t len) __attribute__((nonnull (1,2,3,4)));
*/

void dm_init_packet(DM_PACKET *packet, DM2_AVPGRP *grp) __attribute__((nonnull (1,2)));
void dm_init_avpgrp(void *ctx, void *data, size_t size, DM2_AVPGRP *grp) __attribute__((nonnull (4)));
uint32_t dm_copy_avpgrp(DM2_AVPGRP *dest, DM2_AVPGRP *src) __attribute__((nonnull (1,2)));
uint32_t dm_expect_avp(DM2_AVPGRP *grp, uint32_t *code, uint32_t *vendor_id, void **data, size_t *len) __attribute__((nonnull (1,2,3,4,5)));

uint32_t dm_new_packet(void *ctx, DM2_REQUEST *req, uint32_t code, uint8_t flags, uint32_t appid, uint32_t hopid, uint32_t endid) __attribute__((nonnull (2)));
uint32_t dm_finalize_packet(DM2_REQUEST *req) __attribute__((nonnull (1)));
uint32_t dm_new_group(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id) __attribute__((nonnull (1)));
uint32_t dm_finalize_group(DM2_REQUEST *req) __attribute__((nonnull (1)));
uint32_t dm_put_avp(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, const void *data, size_t len) __attribute__((nonnull (1)));

static inline uint32_t dm_add_object(DM2_REQUEST *req) __attribute__((nonnull (1)));
static inline uint32_t dm_add_raw(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, const void *data, size_t len) __attribute__((nonnull (1)));
static inline uint32_t dm_add_string(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, const char *data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_int8(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int8_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_uint8(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint8_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_int16(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int16_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_uint16(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint16_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_int32(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int32_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_uint32(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint32_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_uint64(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint64_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_int64(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int64_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_float32(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, float data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_float64(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, double data);
static inline uint32_t dm_add_time(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, time_t data) __attribute__((nonnull (1)));
static inline uint32_t dm_add_timeval(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, struct timeval value) __attribute__((nonnull (1)));

uint32_t dm_add_address(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int af, const void *data);
uint32_t dm_add_uint32_get_pos(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint32_t value, size_t *pos) __attribute__((nonnull (1)));
void dm_put_uint32_at_pos(DM2_REQUEST *req, size_t pos, uint32_t value) __attribute__((nonnull (1)));


/* inline functions */

/* operating on dmconfig and AVP headers */

static inline uint32_t
uint24to32(uint8_t i24[3]) {
	return i24[0] << 16 | i24[1] << 8 | i24[2];
}

static inline void
uint32to24(uint8_t i24[3], uint32_t i32) {
	i24[2] = i32 & 0xff;
	i24[1] = (i32 >>  8) & 0xff;
	i24[0] = (i32 >> 16) & 0xff;
}

static inline uint8_t
dm_packet_flags(DM_PACKET *pkt) {
	return pkt->flags;
}

static inline uint32_t
dm_packet_length(DM_PACKET *pkt) {
	return uint24to32(pkt->length);
}

static inline uint32_t
dm_packet_code(DM_PACKET *pkt) {
	return uint24to32(pkt->code);
}

static inline uint32_t
dm_app_id(DM_PACKET *pkt) {
	return ntohl(pkt->app_id);
}

static inline uint32_t
dm_end2end_id(DM_PACKET *pkt) {
	return ntohl(pkt->end2end_id);
}

static inline uint32_t
dm_hop2hop_id(DM_PACKET *pkt) {
	return ntohl(pkt->hop2hop_id);
}

static inline uint32_t
dm_avp_length(DM_AVP *avp) {
	return uint24to32(avp->length);
}

/* inline functions */
static inline uint32_t
dm_add_object(DM2_REQUEST *req)
{
	return dm_new_group(req, AVP_CONTAINER, VP_TRAVELPING);
}

static inline uint32_t
dm_add_raw(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, const void *data, size_t len)
{
	return dm_put_avp(req, code, vendor_id, data, len);
}

static inline uint32_t
dm_add_string(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, const char *data)
{
	return dm_put_avp(req, code, vendor_id, data, strlen(data));
}

static inline uint32_t
dm_add_int8(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int8_t data)
{
	return dm_put_avp(req, code, vendor_id, &data, sizeof(data));
}

static inline uint32_t
dm_add_uint8(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint8_t data)
{
	return dm_put_avp(req, code, vendor_id, &data, sizeof(data));
}

static inline uint32_t
dm_add_int16(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int16_t data)
{
	int16_t val = htons(data);

	return dm_put_avp(req, code, vendor_id, &val, sizeof(val));
}

static inline uint32_t
dm_add_uint16(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint16_t data)
{
	uint16_t val = htons(data);

	return dm_put_avp(req, code, vendor_id, &val, sizeof(val));
}

static inline uint32_t
dm_add_int32(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int32_t data)
{
	int32_t val = htonl(data);

	return dm_put_avp(req, code, vendor_id, &val, sizeof(val));
}

static inline uint32_t
dm_add_uint32(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint32_t data)
{
	uint32_t val = htonl(data);

	return dm_put_avp(req, code, vendor_id, &val, sizeof(val));
}

static inline uint32_t
dm_add_uint64(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, uint64_t data)
{
	uint64_t val = htonll(data);

	return dm_put_avp(req, code, vendor_id, &val, sizeof(val));
}

static inline uint32_t
dm_add_int64(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, int64_t data)
{
	int64_t val = htonll(data);

	return dm_put_avp(req, code, vendor_id, &val, sizeof(val));
}

static inline uint32_t
dm_add_float32(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, float data)
{
	return dm_put_avp(req, code, vendor_id, &data, sizeof(data));
}

static inline uint32_t
dm_add_float64(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, double data)
{
	return dm_put_avp(req, code, vendor_id, &data, sizeof(data));
}

static inline uint32_t
dm_add_time(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, time_t data)
{
	uint32_t dtime;

	if(data + TIME_SINCE_EPOCH > 0xFFFFFFFF)
		return 1;

	dtime = htonl((uint32_t)data + TIME_SINCE_EPOCH);
	return dm_put_avp(req, code, vendor_id, &dtime, sizeof(uint32_t));
}

/* accept only timevals with both fields <= 32 bits (standardization) */
static inline uint32_t
dm_add_timeval(DM2_REQUEST *req, uint32_t code, uint32_t vendor_id, struct timeval value)
{
	DM_TIMEVAL tvalue;

	if(value.tv_sec > (int32_t)0x7FFFFFFF || value.tv_usec >= 1000000)
		return 1;

	tvalue.tv_sec = htonl((uint32_t)value.tv_sec);
	tvalue.tv_usec = htonl((uint32_t)value.tv_usec);

	return dm_put_avp(req, code, vendor_id, &tvalue, sizeof(DM_TIMEVAL));
}

static inline int
dm_get_string_avp(char *dest, size_t dlen, const void *src, size_t slen) {
	size_t len = slen;

	if (len >= dlen)
		len = dlen - 1;

	memcpy(dest, src, len);
	dest[len] = '\0';

	return len;
}

static inline int8_t
dm_get_int8_avp(const void *src) {
	return *(int8_t *)src;
}

static inline uint8_t
dm_get_uint8_avp(const void *src) {
	return *(uint8_t *)src;
}

static inline int16_t
dm_get_int16_avp(const void *src) {
	return ntohs(*(int16_t *)src);
}

static inline uint16_t
dm_get_uint16_avp(const void *src) {
	return ntohs(*(uint16_t *)src);
}

static inline int32_t
dm_get_int32_avp(const void *src) {
	return ntohl(*(int32_t *)src);
}

static inline uint32_t
dm_get_uint32_avp(const void *src) {
	return ntohl(*(uint32_t *)src);
}

static inline int64_t
dm_get_int64_avp(const void *src) {
	return ntohll(*(int64_t *)src);
}

static inline uint64_t
dm_get_uint64_avp(const void *src) {
	return ntohll(*(uint64_t *)src);
}

static inline time_t
dm_get_time_avp(const void *src) {
	uint32_t val = dm_get_uint32_avp(src);

	return val - TIME_SINCE_EPOCH;
}

static inline struct timeval
dm_get_timeval_avp(const void *src) {
	DM_TIMEVAL	*input = (void*)src;
	struct timeval	ret;

	ret.tv_sec = ntohl((uint32_t)input->tv_sec);
	ret.tv_usec = ntohl((uint32_t)input->tv_usec);

	return ret;
}

#endif
