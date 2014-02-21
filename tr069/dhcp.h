/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __DHCP_H
#define __DHCP_H

int start_dhcpd(const char *device, const tr069_selector) __attribute__((nonnull (2)));
void stop_dhcpd(const char *device);

int dhcp_update_wan_ip(const char *wan, const tr069_selector);

const binary_t *dhcp_get_circuit_id(const char *device, struct in_addr addr);
const binary_t *dhcp_get_remote_id(const char *device, struct in_addr addr);

void dm_relay_action(const tr069_selector sel, enum dm_action_type type);

#endif
