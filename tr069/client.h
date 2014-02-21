#ifndef   	CLIENT_H_
#define   	CLIENT_H_

typedef enum {
	AUTH_REQ_NONE      = 0,
	AUTH_REQ_PENDING,
	AUTH_REQ_COMPLETED,
	AUTH_REQ_ERROR,
} authreqstate;

typedef enum {
	AUTH_STATE_NONE      = 0,
	AUTH_STATE_ACCEPTED,
	AUTH_STATE_DENIED,
	AUTH_STATE_ERROR,
} authstate;

typedef enum {
	AUTH_PROV_NONE      = 0,
	AUTH_PROV_ADMIN,
	AUTH_PROV_RADIUS,
	AUTH_PROV_BACKEND,
} authprovider;

typedef enum {
	CLIENT_KNOWN = 0,
	CLIENT_PROBABATION,
	CLIENT_ONLINE,
} CLIENT_STATUS;

#define SESSIONIDSIZE 48

typedef void (*authentication_cb)(int res, struct tr069_value_table *clnt, void *);

struct tr069_value_table *hs_get_zone_by_device(const tr069_selector sel);
struct tr069_value_table *hs_get_zone_by_zoneid(const char *name);
struct tr069_value_table *hs_get_zone_by_id(tr069_id id);

int hs_is_enabled(const tr069_selector sel);

int hs_update_client(tr069_id, int, struct in_addr, const char *, const char *, const char *,
		     const char *, const binary_t *, const binary_t *, const tr069_selector, ticks_t)
	__attribute__((nonnull (10)));
int hs_update_client_by_device(const tr069_selector, int, struct in_addr, const char *, const char *, const char *,
			       const char *, const binary_t *, const binary_t *, const tr069_selector, ticks_t)
	__attribute__((nonnull (1, 10)));

int hs_update_client_called_station(struct tr069_value_table *, int, struct in_addr, const char *, const char *, const uint8_t *, size_t, const uint8_t *, const uint8_t *, unsigned int);
int hs_update_client_from_sol(tr069_id, tr069_id, struct in_addr, const char *, authentication_cb, void *);

int hs_remove_client(tr069_id, struct in_addr, int);
int hs_remove_client_by_zone(struct tr069_value_table *, struct in_addr, int);
int hs_remove_client_by_device(const tr069_selector, struct in_addr, int);

void hs_remove_all_clients_from_zone(struct tr069_value_table *, int);

int scg_set_client_accessclass(const tr069_selector sel, const char *username, char *tag, int cause, const char *user_agent);
int scg_req_client_accessclass(const tr069_selector sel, const char *username, const char *password, char *tag, int cause,
			       const char *user_agent,
			       authentication_cb cb, void *user);
void scg_client_volume_exhausted(struct tr069_value_table *zone, struct tr069_value_table *clnt, int reason);
void dm_clnt_timer_rearm_action(const tr069_selector sel, enum dm_action_type type);

#endif 	    /* !CLIENT_H_ */

