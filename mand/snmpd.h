#ifndef __PURESNMPD_H
#define __PURESNMPD_H

#if defined(WITH_NET_SNMP) || defined(WITH_PURESNMPD)

void start_snmpd(void);
void stop_snmpd(void);
void dm_restart_snmpd_action(const tr069_selector sel, enum dm_action_type type);

#else

static inline void start_snmpd(void) {};
static inline void stop_snmpd(void) {};
static inline void dm_restart_snmpd_action(const tr069_selector sel, enum dm_action_type type) {};

#endif

#endif
