#ifndef __DNSMASQ_INFO_H
#define __DNSMASQ_INFO_H

#define RC_SESSION_ERROR	-1
#define RC_SERVER_ERROR		-2

int dnsmasq_config(void);
int dnsmasq_info(uint32_t diam_code, OBJ_GROUP *obj);

#endif
