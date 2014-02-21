#ifndef __IF_MADWIFI_H
#define __IF_MADWIFI_H

int madwifi_ifup(const char *, const tr069_selector);
void madwifi_ifdown(int card, int ifc);

int madwifi_create_if(const char *, const tr069_selector);
void madwifi_destroy_if(int card, int ifc);

#endif /* __IF_MADWIFI_H */
