#ifndef __FIREWALL_H
#define __FIREWALL_H

#define TABLE_GW_CLASS            "Class"
#define TABLE_GW_HS2INET          "HS2INet"
#define TABLE_GW_HS2RTR           "HT2RtR"
#define TABLE_GW_AUTHSRV          "AuthSrv"
#define TABLE_GW_OUTGOING         "Outgoing"
#define TABLE_GW_INCOMING         "Incoming"
#define TABLE_GW_VALIDATE         "Validate"
#define TABLE_GW_KNOWN            "Known"
#define TABLE_GW_UNKNOWN          "Unknown"
#define TABLE_GW_LOCKED           "Locked"
#define TABLE_GW_WALLGARDEN       "WallGarden"
#define TABLE_GW_WALLGARDEN_IN    "WallGarden_Incoming"
#define TABLE_GW_WALLGARDEN_OUT   "WallGarden_Outgoing"
#define TABLE_GW_MAC              "MAC"
#define TABLE_GW_MAC_OUT          "MAC_Outgoing"
#define TABLE_GW_FILTER           "Filter"
#define TABLE_GW_CLASSIFY         "Classify"

#define IPSET_GW_HS2INET          "HS2INet"

enum {
    FW_MARK_PROBATION = 1,   /**< @brief The client is in probation period and must be authenticated */
    FW_MARK_KNOWN = 2,       /**< @brief The client is known to the firewall */
    FW_MARK_MAC = 3,         /**< @brief The MAC of this client is preconfigure in the firewall as ACCEPT */
    FW_MARK_LOCKED = 254     /**< @brief The client has been locked out */
};

void ipt_init(void);
void scg_acl_init(void);

void set_fw_wan_nat(tr069_id);

void dm_proxy_action(const tr069_selector, enum dm_action_type);
void dm_firewall_action(const tr069_selector, enum dm_action_type);
void dm_scg_acl_action(const tr069_selector, enum dm_action_type);

#endif
