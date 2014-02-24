#ifndef   	SESSION_H_
#define   	SESSION_H_

int fw_allow(tr069_id, struct tr069_value_table *, struct tr069_value_table *);
int fw_deny(tr069_id, struct tr069_value_table *, struct tr069_value_table *);

int fw_natp_create(struct tr069_value_table *, struct tr069_value_table *);
int fw_natp_remove(struct tr069_value_table *, struct tr069_value_table *);
int fw_clnt_cleanup(struct tr069_value_table *);

//int iptables_fw_counters_update(int iface);
int scg_zones_init(void);
int start_scg_zones(void);

void dm_zone_action(const tr069_selector, enum dm_action_type);
void dm_l3policy_action(const tr069_selector, enum dm_action_type);

#endif 	    /* !SESSION_H_ */
