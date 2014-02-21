#ifndef _GW_RADIUS_H_
#define _GW_RADIUS_H_

#include "tr069_token.h"
#include "tr069_action.h"
#include "tr069_store.h"

#include "client.h"

#if defined (HAVE_LIBPOLARSSL)
#include <polarssl/havege.h>

extern havege_state h_state;
#endif

typedef enum {
	PWENC_RFC       = 0,
	PWENC_TPOSS,
} pwencode;

#define	INADDR_NAS_SELECT	htonl((in_addr_t) 0xfffffffe)

void init_scg_zones_radius(void);
void stop_scg_zones_radius(void);

void dm_rad_srv_action(const tr069_selector, enum dm_action_type);
void dm_zone_rad_srv_action(const tr069_selector, enum dm_action_type);

int radius_accounting_request(int, struct tr069_value_table *, int);

int radius_authentication_request(const tr069_selector, struct tr069_value_table *,
				  const tr069_selector, struct tr069_value_table *,
				  const char *sessionid,
				  const char *username, const char *password,
				  const char *tag, int request_cui, int auth_only,
				  authentication_cb, authentication_cb, void *)
	__attribute__((nonnull (1,3)));

void radius_accounting_on(struct tr069_value_table *);
void radius_accounting_off(struct tr069_value_table *, int);

#endif /* _GW_RADIUS_H_ */
