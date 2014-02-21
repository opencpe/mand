#ifndef __IPPOOL_H
#define __IPPOOL_H

int alloc_natpool_addr(struct tr069_value_table *, struct in_addr, struct in_addr *, unsigned int *, unsigned int *);
void release_natpool_addr(struct tr069_value_table *, struct in_addr, unsigned int);
int check_natpool_addr(struct tr069_value_table *, struct in_addr, unsigned int);

#endif
