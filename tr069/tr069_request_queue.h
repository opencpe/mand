/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 */

#ifndef __TR069_REQUEST_QUEUE_H
#define __TR069_REQUEST_QUEUE_H

#include <stdio.h>

#include "tr069.h"
#include "soapH.h"

enum req_cpe {
	REQ_CPE_KICKED = 0,
	/* cumulative: */
	REQ_CPE_TRANS_COMPL
#define REQ_CPE_MAX \
	REQ_CPE_TRANS_COMPL
};

int tr069_add_transfer_complete_request(xsd__string, struct cwmp__FaultStruct,
					xsd__dateTime, xsd__dateTime);
int tr069_add_kicked_request(xsd__string, xsd__string, xsd__string, xsd__string);

void tr069_clear_request_by_type(enum req_cpe id);
int tr069_dispatch_queued_requests(struct soap *, const char *, const char *);

void tr069_serialize_xml_chardata(FILE *fout, const char *str);
void tr069_serialize_requests(FILE *fout);
void tr069_deserialize_requests(FILE *fin);

#endif
