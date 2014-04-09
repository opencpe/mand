/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DMCONFIG_H
#define __DMCONFIG_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/queue.h>
#include <ev.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "dmmsg.h"
#include "libdmconfig/codes.h"
#include "libdmconfig/dmcontext.h"

extern int dmconfig_debug_level;

#define DM_ADD_INSTANCE_AUTO		0x8000

/*
 * request-specific flags
 * NOTE: they have to be kept in-sync with erldmconfig's dmconfig.hrl
 */

		/* start session flags */

#define CMD_FLAG_READWRITE		0x0
#define CMD_FLAG_CONFIGURE		(1 << 0)

/* function headers */

/* API v2 */

struct dm_bin {
	void *data;
	size_t size;
};

struct dm2_avp {
	uint32_t code;
	uint32_t vendor_id;
	void *data;
	size_t size;
};

typedef struct dmc_request {
	uint32_t hop2hop;
	uint32_t end2end;
	uint32_t code;
	uint32_t sessionid;
} DMC_REQUEST;

uint32_t dm_decode_unknown_as_string(uint32_t type, void *data, size_t len, char **val);

uint32_t dm_expect_end(DM2_AVPGRP *grp) __attribute__((nonnull (1)));
uint32_t dm_expect_object(DM2_AVPGRP *grp, DM2_AVPGRP *obj) __attribute__((nonnull (1,2)));
uint32_t dm_expect_raw(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, void **data, size_t *size) __attribute__((nonnull (1,4,5)));
uint32_t dm_expect_value(DM2_AVPGRP *grp, struct dm2_avp *avp) __attribute__((nonnull (1,2)));
uint32_t dm_expect_bin(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, struct dm_bin *bin) __attribute__((nonnull (1,4)));
uint32_t dm_expect_string_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, char **value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_uint8_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint8_t *value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_uint16_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint16_t *value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_uint32_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, uint32_t *value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_int8_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int8_t *value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_int16_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int16_t *value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_int32_type(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, int32_t *value) __attribute__((nonnull (1,4)));
uint32_t dm_expect_group(DM2_AVPGRP *grp, uint32_t exp_code, uint32_t exp_vendor_id, DM2_AVPGRP *obj) __attribute__((nonnull (1,4)));
uint32_t dm_expect_group_end(DM2_AVPGRP *grp) __attribute__((nonnull (1)));

DM2_REQUEST *dm_new_request(void *ctx, uint32_t code, uint8_t flags, uint32_t hopid, uint32_t endid);

#endif /* __DMCONFIG_H */
