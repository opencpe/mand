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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <ev.h>

#if defined (HAVE_LIBPOLARSSL)
#include <polarssl/havege.h>

extern havege_state h_state;
#endif

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_index.h"

#define SDEBUG
#include "debug.h"

#include "ifup.h"
#include "if_device.h"
#include "bitmap.h"
#include "dhcp.h"
#include "dhcp_internal.h"
#include "client.h"

/* Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 */

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO      0x9e3779b9

/* NOTE: Arguments are modified. */
#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
static inline uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += initval;

        __jhash_mix(a, b, c);

        return c;
}

static inline uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval)
{
        return jhash_3words(a, b, 0, initval);
}

static inline uint32_t jhash_1word(uint32_t a, uint32_t initval)
{
        return jhash_3words(a, 0, 0, initval);
}

static const char *ip2str(struct in_addr ipaddr, char *buf)
{
	return inet_ntop(AF_INET, &ipaddr, buf, INET_ADDRSTRLEN);
}

/*
 *
 */

struct network_pool {
	int refcnt;
	uint32_t base;
	uint32_t size;
	bits_t leases[];
};

struct ip_pool {
	struct network_pool *network;
	uint32_t size;
	uint32_t min;
	uint32_t max;
	unsigned int initval;
};

static struct network_pool *new_network_pool(uint32_t base, uint32_t size)
{
	int rest;
	struct network_pool *pool;

	pool = malloc(sizeof(struct network_pool) + sizeof(bits_t) * map_size(size));
	if (!pool)
		return NULL;

	memset(pool, 0, sizeof(struct network_pool) + sizeof(bits_t) * map_size(size));
	rest = bits_size * map_size(size) - size;
	if (rest)
		/* mark bits at the end of the map as used */
		pool->leases[map_size(size) - 1] = UINT_MAX << (bits_size - rest);
	pool->base = base;
	pool->size = size;

	return pool;
}

static struct ip_pool *new_ip_pool(struct network_pool *network, uint32_t min, uint32_t max)
{
	struct ip_pool *pool;

	if (min > max)
		return NULL;

	pool = malloc(sizeof(struct ip_pool));
	if (!pool)
		return NULL;

	memset(pool, 0, sizeof(struct ip_pool));
	pool->network = network;
	network->refcnt++;
	pool->size = max - min + 1;   /* min and max are inclusive */
	pool->min = min - network->base;
	pool->max = max - network->base;
	pool->initval = havege_rand(&h_state);

	return pool;
}

static inline void free_ip_pool(struct ip_pool *pool)
{
	if (pool) {
		pool->network->refcnt--;
		if (!pool->network->refcnt)
			free(pool->network);
	}
	free(pool);
}

/* get the first bit in a pool that is not set and >= min and <= max */

/* return a bitmask with all bits > bit set */
#define MASK_LOW(bit) (UINT_MAX >> (bits_size - (bit)))

/* return a bitmask with all bits > bit set */
#define MASK_HIGH(bit) (UINT_MAX << ((bit) + 1))

/* get a mask to make all out-of-range bits as used */
static bits_t get_mask(unsigned int minpos, unsigned int minbit,
		       unsigned int maxpos, unsigned int maxbit,
		       unsigned int pos)
{
	bits_t mask = 0;

	/* mark all bits that are not part of this range as used */
	if (pos == minpos && minbit != 0) mask |= MASK_LOW(minbit);
	if (pos == maxpos && maxbit + 1 != bits_size) mask |= MASK_HIGH(maxbit);

	return mask;
}

/* get a bit that is within the range */
static unsigned int get_bit(bits_t p, bits_t mask, unsigned int bit)
{
	p |= mask;
	if (p & (1 << bit))
		bit = (ffs(~ror(p, bit)) - 1 + bit) % bits_size;

	return bit;
}

static int allocate_lease(struct ip_pool *pool, uint32_t hash)
{
	unsigned int lease;
	unsigned int pos, spos;
	unsigned int bit;
	bits_t mask;
	struct network_pool *network = pool->network;

	/* Note:
	 *  we can not trust the used accouting, as overlaping pools, network borders and static assignment are not accounted for
	 */

	unsigned int minpos = pool->min / bits_size;
	unsigned int minbit = pool->min % bits_size;
	unsigned int maxpos = pool->max / bits_size;
	unsigned int maxbit = pool->max % bits_size;

	lease = pool->min + (hash % pool->size);
	spos = pos = lease / bits_size;
	bit = lease % bits_size;

	mask = get_mask(minpos, minbit, maxpos, maxbit, pos);
	for (; pos < maxpos; pos++) {
		if ((network->leases[pos] | mask) != UINT_MAX)
			break;
		mask = 0;
	}

	/* either got an inner elememnt or the last one,
	 * mask will take care of making any bits outside the current range as used */
	mask = get_mask(minpos, minbit, maxpos, maxbit, pos);
	if ((network->leases[pos] | mask) != UINT_MAX) {
		bit = get_bit(network->leases[pos], mask, bit);
		lease = (pos * bits_size) + bit;
	} else if (pos == minpos) {
		/* did not find a lease, we are at the start of the pool
		 * this can only happen if the pool fits within one word */
		return -1;
	} else {
		mask = get_mask(minpos, minbit, maxpos, maxbit, minpos);
		for (pos = minpos; pos < spos; pos++) {
			if ((network->leases[pos] | mask) != UINT_MAX)
				break;
			mask = 0;
		}

		if (pos >= spos)
			return -1;

		/* it should be: minpos < pos < maxpos, all other case have ben handled above */
		assert(minpos <= pos);
		assert(pos < maxpos);

		bit = get_bit(network->leases[pos], mask, bit);
		lease = (pos * bits_size) + bit;
	}

	map_set_bit(network->leases, lease);
	return lease;
}

static void release_lease(struct ip_pool *pool, int lease)
{
	struct network_pool *network = pool->network;

	if (lease < INT_MAX && (unsigned int)lease >= pool->min && (unsigned int)lease <= pool->max)
		map_clear_bit(network->leases, lease);
}

static void prealloc_netaddr(struct network_pool *network)
{
	for (unsigned int i = 0; i < network->size; i += 256) {
		map_set_bit(network->leases, i);
		if (i + 255 < network->size)
			map_set_bit(network->leases, i + 255);
	}
}

static void prealloc_static_addrs(struct tr069_value_table *dhcpt, struct ip_pool *pool)
{
	struct network_pool *network = pool->network;
	tr069_id id;
        struct tr069_instance *slease;
        struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress */
	id = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStaticAddress;
	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress */
		id = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPStaticAddress;

	slease = tr069_get_instance_ref_by_id(dhcpt, id);
	if (!slease) {
		EXIT();
		return;
	}

        for (node = tr069_instance_first(slease);
             node != NULL;
             node = tr069_instance_next(slease, node))
	{
		uint32_t ip;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i].Enable */
		if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Enable))
			continue;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i].Yiaddr */
		ip = ntohl(tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Yiaddr).s_addr);
		if (ip == 0 || ip < network->base)
			continue;

		ip -= network->base;
		if (ip < network->size)
			map_set_bit(network->leases, ip);
	}

	EXIT();
}

static void alloc_ipaddr(struct tr069_value_table *dhcpt, struct in_addr ipaddr)
{
	tr069_id poffs = 0;
	struct ip_pool *pool;
	struct network_pool *network;
	uint32_t ip;

	ENTER();

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);

	pool = tr069_get_ptr_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
	if (!pool) {
		EXIT();
		return;
	}

	network = pool->network;
	ip = ntohl(ipaddr.s_addr);
	if (ip == 0 || ip < network->base) {
		EXIT();
		return;
	}

	ip -= network->base;
	if (ip < network->size)
		map_set_bit(network->leases, ip);

	EXIT();
}

int alloc_dhcp_addr(struct tr069_value_table *dhcpt, const uint8_t chaddr[DHCP_CHADDR_LEN], struct in_addr *addr)
{
#if defined(SDEBUG)
	char ip[INET6_ADDRSTRLEN];
#endif
	tr069_id poffs = 0;
	struct ip_pool *pool;
	int lease;
	uint32_t hash;

	ENTER();

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);

	pool = tr069_get_ptr_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
	if (!pool) {
		EXIT();
		return 0;
	}

	hash = jhash_2words(*(uint32_t *)&chaddr[0], *(uint32_t *)&chaddr[4], pool->initval);
	lease = allocate_lease(pool, hash);
	if (lease < 0) {
		EXIT();
		return 0;
	}

	addr->s_addr = htonl(pool->network->base + lease);

	debug(": allocated: %s", ip2str(*addr, ip));
	EXIT();
	return 1;
}

/*
 * allocate the given address if it is valid and has not been taken
 */
static int try_alloc_dhcp_addr(struct tr069_value_table *dhcpt, struct in_addr addr)
{
	tr069_id poffs = 0;
	struct ip_pool *pool;
	struct network_pool *network;
	uint32_t lease;

	ENTER();

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);

	pool = tr069_get_ptr_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
	if (!pool) {
		EXIT();
		return 0;
	}

	network = pool->network;
	lease = ntohl(addr.s_addr);
	debug(": base: %u, lease: %u", network->base, lease);
	if (lease == 0 || lease < network->base) {
		EXIT();
		return 0;
	}

	lease -= network->base;
	if (lease > network->size || lease < pool->min || lease > pool->max) {
		EXIT();
		return 0;
	}

	if (map_get_bit(network->leases, lease) == 0) {
		map_set_bit(network->leases, lease);
		EXIT();
		return 1;
	}

	EXIT();
	return 0;
}

void release_dhcp_addr(struct tr069_value_table *dhcpt, struct in_addr addr)
{
	tr069_id poffs = 0;
	struct ip_pool *pool;
	struct network_pool *network;
	uint32_t lease;

	ENTER();

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.X_DM_PoolInfo */
	pool = tr069_get_ptr_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
	if (!pool)
		return;

	network = pool->network;
	lease = ntohl(addr.s_addr);
	if (lease == 0 || lease < network->base) {
		EXIT();
		return;
	}

	lease -= network->base;
	release_lease(pool, lease);
	EXIT();

}

#define OPT_PTR(pkt, offs) ((struct dhcp_opt *)(((uint8_t *)pkt) + offs))

static void add_opt_raw(struct dhcp_packet *pkt, size_t *len, uint8_t op, uint8_t op_len, const uint8_t *data)
{
	struct dhcp_opt *opt;

	if (*len + op_len + 2 >= DHCP_MAX_REPLY_LEN)
		return;

	opt = OPT_PTR(pkt, *len);
	opt->op = op;
	opt->len = op_len;
	if (op_len && data)
		memcpy(opt->data, data, op_len);
	*len += 2 + op_len;
}

static void add_opt_uint8(struct dhcp_packet *pkt, size_t *len, uint8_t op, uint8_t i)
{
	add_opt_raw(pkt, len, op, 1, &i);
}

static void add_opt_uint32(struct dhcp_packet *pkt, size_t *len, uint8_t op, uint32_t i)
{
	add_opt_raw(pkt, len, op, 4, (uint8_t *)&i);
}

static int in_same_network(struct in_addr a, struct in_addr b, struct in_addr netmask)
{
	return ((a.s_addr & netmask.s_addr)  == (b.s_addr & netmask.s_addr));
}

static struct in_addr get_primary_ip(struct tr069_value_table *land)
{
	struct in_addr ip = { .s_addr = INADDR_NONE };
	struct tr069_value_table *lhcm;
        struct tr069_instance *ipif;
        struct tr069_instance_node *node;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
	lhcm = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_LANHostConfigManagement);
	if (!lhcm) {
		EXIT();
		return ip;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface */
	ipif = tr069_get_instance_ref_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_IPInterface);
	if (!ipif) {
		EXIT();
		return ip;
	}

        for (node = tr069_instance_first(ipif);
             node != NULL;
             node = tr069_instance_next(ipif, node))
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.Enable */
		if (tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_Enable)) {
			EXIT();
			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPInterface.{i}.IPInterfaceIPAddress */
			return tr069_get_ipv4_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_IPInt_j_IPInterfaceIPAddress);
		}

	EXIT();
	return ip;
}

static void add_opt_addr_list(struct dhcp_packet *pkt, size_t *len, uint8_t op, const char *str)
{
	while (str && *str) {
		const char *p;
		char ip[INET_ADDRSTRLEN];
		struct in_addr ipaddr;

		p = strchr(str, ',');
		if (!p) {
			strncpy(ip, str, sizeof(ip));
			ip[sizeof(ip) - 1] = '\0';
		} else {
			unsigned int l = p - str;
			if (l >= sizeof(ip))
				l = sizeof(ip) - 1;
			strncpy(ip, str, l);
			ip[l] = '\0';
		}

		inet_pton(AF_INET, ip, &ipaddr);
		add_opt_uint32(pkt, len, op, ipaddr.s_addr);

		if (!p)
			break;

		str = p + 1;
	}
}


static int cmp_byte(const void *p1, const void *p2)
{
	return (int)(*(uint8_t *)p1) - (int)(*(uint8_t *)p2);
}

static void tr069_set_string_from_opt_by_id(struct tr069_value_table *t, tr069_id id,
					   struct dhcp_packet *req, uint16_t offs)
{
	uint8_t tmp;
	struct dhcp_opt *opt;

	if (!offs)
		return;

	opt = OPT_PTR(req, offs);

	tmp = opt->data[opt->len]; opt->data[opt->len] = '\0';
	tr069_set_string_by_id(t, id, opt->data);
	opt->data[opt->len] = tmp;
}

static void tr069_set_binary_from_opt_by_id(struct tr069_value_table *t, tr069_id id,
					    struct dhcp_packet *req, uint16_t offs)
{
	struct dhcp_opt *opt;

	if (!offs)
		return;

	opt = OPT_PTR(req, offs);

	tr069_set_binary_data_by_id(t, id, opt->len, opt->data);
}

static int cond_opt(struct dhcp_req *req, uint8_t op)
{
	if (!req->sopt_req_list_len)
		return 1;

	return bsearch(&op, req->sopt_req_list, req->sopt_req_list_len, 1, cmp_byte) != NULL;
}

static struct tr069_instance_node *get_host_by_ip(struct tr069_value_table *land, struct in_addr ipaddr)
{
	struct tr069_value_table *hosts;
	struct tr069_instance *hostt;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts */
	hosts = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_Hosts);
	if (!hosts) {
		EXIT();
		return NULL;
	}
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host */
	hostt = tr069_get_instance_ref_by_id(hosts, cwmp__IGD_LANDev_i_Hosts_Host);
	if (!hostt) {
		EXIT();
		return NULL;
	}

	EXIT();
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
	return find_instance(hostt, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, T_IPADDR4, &init_DM_IP4(ipaddr, 0));
}

static void build_host_id(struct dhcp_req *req, binary_t *b)
{
	int len = 0;
	uint8_t type;
	uint8_t *data = NULL;

	if (req->client_id) {
		struct dhcp_opt *opt;

		opt = OPT_PTR(req->request, req->client_id);
		if (opt->len > 0) {
			type = opt->data[0];
			data = &opt->data[1];
			len = opt->len - 1;
		}
	}
	if (!data) {
		type = req->request->htype;
		len =  req->request->hlen;
		data = &req->request->chaddr;
	}

	if (len > 255)
		len = 255;
	else if (len < 0)
		len = 0;

	b->len = len + 1;
	b->data[0] = type;
	if (len != 0)
		memcpy(&b->data[1], data, len);
}

static struct tr069_instance_node *get_host_by_id(struct tr069_value_table *land, struct dhcp_req *req)
{
	struct tr069_value_table *hosts;
	struct tr069_instance *hostt;
	struct tr069_instance_node *r;

	uint8_t bval[sizeof(binary_t) + 256];
	binary_t *b = (binary_t *)&bval;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts */
	hosts = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_Hosts);
	if (!hosts) {
		EXIT();
		return NULL;
	}
	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host */
	hostt = tr069_get_instance_ref_by_id(hosts, cwmp__IGD_LANDev_i_Hosts_Host);
	if (!hostt) {
		EXIT();
		return NULL;
	}

	build_host_id(req, b);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_DM_HostID */
	r = find_instance(hostt, cwmp__IGD_LANDev_i_Hosts_H_j_X_DM_HostID, T_BINARY, &init_DM_BINARY(b, 0));

	EXIT_MSG(": return host %p", r);
	return r;
}

static void update_lease_host(struct tr069_value_table *host, const tr069_selector l2dev, struct dhcp_req *req)
{
	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Layer2Interface */
	tr069_set_selector_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_Layer2Interface, l2dev);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_RelayAgentAddress */
	tr069_set_ipv4_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_RelayAgentAddress, req->request->giaddr);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.VendorClassID */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_VendorClassID,
					req->request, req->vendor_id);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.VendorClassID */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_VendorClassID,
					req->request, req->vendor_id);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.UserClassID */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_UserClassID,
					req->request, req->user_class);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.HostName */
	tr069_set_string_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_HostName,
					req->request, req->host_name);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Active */
	tr069_set_bool_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_Active, 1);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPRequestOptionList */
	tr069_set_binary_data_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPRequestOptionList,
				    req->opt_list_len, req->opt_list);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPParameterRequestList */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPParameterRequestList,
					req->request, req->opt_req_list);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentCircuitId */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentCircuitId,
					req->request, req->agent_circuit_id);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentRemoteId,
					req->request, req->agent_remote_id);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_SubScriberId */
	tr069_set_binary_from_opt_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_SubScriberId,
					req->request, req->agent_subscriber_id);

	EXIT();
}

static struct tr069_instance_node *add_lease_host(struct tr069_value_table *land, const tr069_selector l2dev, struct dhcp_req *req)
{
	struct tr069_instance_node *host;
	char mac[18];
	uint8_t bval[sizeof(binary_t) + 256];
	binary_t *b = (binary_t *)&bval;
	tr069_id id = TR069_ID_AUTO_OBJECT;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i} */
	if ((host = tr069_add_instance_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
						cwmp__IGD_LANDevice,
						land->id[2],
						cwmp__IGD_LANDev_i_Hosts,
						cwmp__IGD_LANDev_i_Hosts_Host, 0}, &id)) == NULL) {
		EXIT();
		return NULL;
	}

	build_host_id(req, b);
	tr069_set_binary_by_id(DM_TABLE(host->table),
			       cwmp__IGD_LANDev_i_Hosts_H_j_X_DM_HostID, b);

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 req->request->chaddr[0], req->request->chaddr[1], req->request->chaddr[2],
		 req->request->chaddr[3], req->request->chaddr[4], req->request->chaddr[5]);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.MACAddress */
	tr069_set_string_by_id(DM_TABLE(host->table),
			       cwmp__IGD_LANDev_i_Hosts_H_j_MACAddress, mac);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.ClientID */
	tr069_set_binary_from_opt_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_ClientID,
					req->request, req->client_id);

	update_lease_host(DM_TABLE(host->table), l2dev, req);

	EXIT();
	return host;
}

static void remove_lease(struct tr069_value_table *host)
{
	ENTER();

	tr069_del_object_by_selector(host->id);

	EXIT();
}

static void prepare_reply(struct dhcp_req *req)
{
	memcpy(req->answer, req->request, offsetof(struct dhcp_packet, sname));
	req->answer->op = BOOTREPLY;
	req->answer->hops = 0;
	req->answer->secs = 0;

	req->answer->giaddr = req->request->giaddr;

	memset(req->answer->sname, 0, DHCP_MAX_REPLY_LEN - offsetof(struct dhcp_packet, sname));

	if (req->flags | F_DHCPREQ) {
		*(uint32_t *)req->answer->options = DHCP_COOKIE;
		req->repl_len += 4;
	}
}

struct host_info {
	ev_timer timer;
};

static void host_expire(EV_P_ ev_timer *w, int revents __attribute__ ((unused)))
{
	struct tr069_value_table *host;

	ENTER();

	host = w->data;
	assert(host);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_State */
	if (tr069_get_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State) == cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_Active) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_State */
		tr069_set_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State, cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_DHCPExpired);

		/* remove it from the SCG Zone */
		hs_remove_client_by_device(
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Layer2Interface */
			*tr069_get_selector_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_Layer2Interface),
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
			tr069_get_ipv4_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress),
			0);

		/* keep expired leases for 60 seconds arround */
		w->repeat = 60.;
		ev_timer_again(EV_DEFAULT_ w);

		EXIT();
		return;
	}

	remove_lease(host);
	EXIT();
}

static void set_lease_time(struct tr069_value_table *host, int32_t lease_time)
{
	struct host_info *hi;

	ENTER();

	if (lease_time <= 0) {
		tr069_set_int_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining, lease_time);
		EXIT();
		return;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.LeaseTimeRemaining */
	tr069_set_int_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining, lease_time + monotonic_time());

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_DM_HostInfo */
	hi = tr069_get_ptr_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_DM_HostInfo);
	if (!hi) {
		hi = malloc(sizeof(struct host_info));
		if (!hi) {
			EXIT();
			return;
		}

		ev_init(&hi->timer, host_expire);
		hi->timer.data = host;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_DM_HostInfo */
		tr069_set_ptr_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_DM_HostInfo, hi);
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_State */
	switch (tr069_get_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State)) {
	case cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_DHCPOffered:
	case cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_Invalid:
		/* keep Invalid and Offered lease for 30 seconds arround */
		hi->timer.repeat = 30.;
		break;

	default:
		hi->timer.repeat = lease_time;
		break;
	}

	ev_timer_again(EV_DEFAULT_ &hi->timer);

	EXIT();
}

static void add_lease_time_option(struct tr069_value_table *dhcpt,
				  struct tr069_value_table *host,
				  struct dhcp_req *req)
{
	tr069_id poffs = 0;
	int32_t lease_time;

	ENTER();

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPLeaseTime */
	lease_time = tr069_get_int_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_DHCPLeaseTime);

	add_opt_uint32(req->answer, &req->repl_len, OPT_LEASE_TIME, htonl((uint32_t)lease_time));
	if (lease_time > 0) {
		add_opt_uint32(req->answer, &req->repl_len, OPT_T1, htonl(lease_time/2));
		add_opt_uint32(req->answer, &req->repl_len, OPT_T2, htonl((lease_time*7)/8));
	}
	set_lease_time(host, lease_time);
}

static void add_lease_options(struct tr069_value_table *dhcpt,
			      struct in_addr ipaddr,
			      struct dhcp_req *req)
{
	tr069_id poffs = 0;
	tr069_id opt_offs = 0;
	struct dhcp_opt *opt;
	struct in_addr netmask;
	const char *str;
	struct tr069_instance *dhcpopts;

	ENTER();

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool) {
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
		opt_offs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPOption - cwmp__IGD_LANDev_i_HostCfgMgt_DHCPOption);
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.SubnetMask */
	netmask = tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_SubnetMask);

	if (cond_opt(req, OPT_SUBNET_MASK))
		add_opt_uint32(req->answer, &req->repl_len, OPT_SUBNET_MASK, netmask.s_addr);

	if (cond_opt(req, OPT_BROADCAST)) {
		struct in_addr bcast;

		bcast.s_addr = ipaddr.s_addr | ~netmask.s_addr;
		add_opt_uint32(req->answer, &req->repl_len, OPT_BROADCAST, bcast.s_addr);
	}

	if (cond_opt(req, OPT_ROUTER)) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.IPRouters */
		str = tr069_get_string_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_IPRouters);
		add_opt_addr_list(req->answer, &req->repl_len, OPT_ROUTER, str);
	}

	if (cond_opt(req, OPT_DNSSERVER)) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DNSServers */
		str = tr069_get_string_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_DNSServers);
		add_opt_addr_list(req->answer, &req->repl_len, OPT_DNSSERVER, str);
	}

	if (cond_opt(req, OPT_DOMAINNAME)) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DomainName */
		str = tr069_get_string_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_DomainName);
		if (str && *str)
			add_opt_raw(req->answer, &req->repl_len, OPT_DOMAINNAME, strlen(str), str);
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption */
	dhcpopts = tr069_get_instance_ref_by_id(dhcpt, opt_offs + cwmp__IGD_LANDev_i_HostCfgMgt_DHCPOption);
	if (dhcpopts) {
		struct tr069_instance_node *node;

		for (node = tr069_instance_first(dhcpopts);
		     node != NULL;
		     node = tr069_instance_next(dhcpopts, node))
		{
			unsigned int tag;
			const binary_t *bval;
			struct tr069_value_table *val = DM_TABLE(node->table);

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption.{i}.Enable */
			if (!tr069_get_bool_by_id(val, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPOption_j_Enable))
				continue;

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption.{i}.Tag */
			tag = tr069_get_uint_by_id(val, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPOption_j_Tag);
			if (tag == OPT_SUBNET_MASK ||
			    tag == OPT_BROADCAST ||
			    tag == OPT_ROUTER ||
			    tag == OPT_DNSSERVER ||
			    tag == OPT_DOMAINNAME ||
			    tag == OPT_AGENT_ID ||
			    tag == OPT_LEASE_TIME ||
			    tag == OPT_MESSAGE_TYPE ||
			    tag == OPT_REQUESTED_OPTS ||
			    tag == OPT_SERVER_IDENTIFIER ||
			    tag == OPT_CLIENT_ID ||
			    tag == OPT_USER_CLASS ||
			    tag == OPT_END ||
			    !cond_opt(req, tag))
				continue;

			/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPOption.{i}.Value */
			bval = tr069_get_binary_by_id(val, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPOption_j_Value);
			if (!bval || bval->len == 0)
				continue;

			add_opt_raw(req->answer, &req->repl_len, tag, bval->len, bval->data);
		}
	}

	if (req->agent_id) {
		opt = OPT_PTR(req->request, req->agent_id);
		add_opt_raw(req->answer, &req->repl_len, OPT_AGENT_ID, opt->len, opt->data);
	}

	EXIT();
}

static struct tr069_value_table *get_static_lease_by_chaddr(struct tr069_value_table *dhcpt, uint8_t chaddr[DHCP_CHADDR_LEN])
{
	tr069_id id;
	struct tr069_instance *slease;
	struct tr069_instance_node *host;
	char mac[18];

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress */
	id = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStaticAddress;
	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress */
		id = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPStaticAddress;

	slease = tr069_get_instance_ref_by_id(dhcpt, id);
	if (!slease) {
		EXIT();
		return NULL;
	}

	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		 chaddr[0], chaddr[1], chaddr[2],
		 chaddr[3], chaddr[4], chaddr[5]);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Chaddr */
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress.{i}.Chaddr */
	host = find_instance(slease, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Chaddr, T_STR, &init_DM_STRING(mac, 0));
	if (!host) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Enable */
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress.{i}.Enable */
	if (!tr069_get_bool_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Enable)) {
		EXIT();
		return NULL;
	}

	EXIT();
	return DM_TABLE(host->table);
}

static struct tr069_value_table *get_static_lease_by_ip(struct tr069_value_table *dhcpt, struct in_addr ipaddr)
{
	tr069_id id;
	struct tr069_instance *slease;
	struct tr069_instance_node *host;

	ENTER();

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress */
	id = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStaticAddress;
	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress */
		id = cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_DHCPStaticAddress;

	slease = tr069_get_instance_ref_by_id(dhcpt, id);
	if (!slease) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Yiaddr */
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress.{i}.Yiaddr */
	host = find_instance(slease, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Yiaddr, T_IPADDR4, &init_DM_IP4(ipaddr, 0));
	if (!host) {
		EXIT();
		return NULL;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Enable */
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.DHCPStaticAddress.{i}.Enable */
	if (!tr069_get_bool_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Enable)) {
		EXIT();
		return NULL;
	}

	EXIT();
	return DM_TABLE(host->table);

}

static int subsearch(struct dhcp_opt *opt, const binary_t *bval)
{
	for (unsigned int i = 0; i <= opt->len - bval->len; i++)
		if (memcmp(&opt->data[i], bval->data, bval->len) == 0)
			return 1;

	return 0;
}

static int match_vendorid(struct tr069_value_table *dhcpt, struct dhcp_req *req)
{
	int verdict = 0;
	const binary_t *bval;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.VendorClassID */
	bval = tr069_get_binary_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassID);
	if (!bval || bval->len == 0)
		return 1;

	if (req->vendor_id) {
		struct dhcp_opt *opt;

		opt = OPT_PTR(req->request, req->vendor_id);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.VendorClassIDMode */
		switch(tr069_get_enum_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassIDMode)) {
		case cwmp___IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassIDMode_Exact:
			verdict = (opt->len == bval->len) &&
				memcmp(opt->data, bval->data, bval->len) == 0;
			break;

		case cwmp___IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassIDMode_Prefix:
			verdict = (opt->len >= bval->len) &&
				memcmp(opt->data, bval->data, bval->len) == 0;
			break;

		case cwmp___IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassIDMode_Suffix:
			verdict = (opt->len >= bval->len) &&
				memcmp(&opt->data[opt->len - bval->len], bval->data, bval->len) == 0;
			break;

		case cwmp___IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassIDMode_Substring:
			verdict = (opt->len >= bval->len) &&
				subsearch(opt, bval);
			break;
		}
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.VendorClassIDExclude */
	if (tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_VendorClassIDExclude))
		verdict = !verdict;

	return verdict;
}

static int match_clientid(struct tr069_value_table *dhcpt, struct dhcp_req *req)
{
	int verdict = 0;
	const binary_t *bval;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.ClientID */
	bval = tr069_get_binary_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_ClientID);
	if (!bval || bval->len == 0)
		return 1;

	if (req->client_id) {
		struct dhcp_opt *opt;

		opt = OPT_PTR(req->request, req->client_id);

		verdict = (opt->len == bval->len) &&
			memcmp(opt->data, bval->data, bval->len) == 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.ClientIDExclude */
	if (tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_ClientIDExclude))
		verdict = !verdict;

	return verdict;
}

static int match_userclassid(struct tr069_value_table *dhcpt, struct dhcp_req *req)
{
	int verdict = 0;
	const binary_t *bval;

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.UserClassID */
	bval = tr069_get_binary_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_UserClassID);
	if (!bval || bval->len == 0)
		return 1;

	if (req->user_class) {
		struct dhcp_opt *opt;

		opt = OPT_PTR(req->request, req->user_class);

		verdict = (opt->len == bval->len) &&
			memcmp(opt->data, bval->data, bval->len) == 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.UserClassIDExclude */
	if (tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_UserClassIDExclude))
		verdict = !verdict;

	return verdict;
}

static int match_chaddr(struct tr069_value_table *dhcpt, struct dhcp_req *req)
{
	int verdict = 1;
	const char *s;

	uint8_t chaddr[6];
	uint8_t mask[6];

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.Chaddr */
	s = tr069_get_string_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_Chaddr);
	if (!s || *s == '\0')
		return 1;

	if (sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		   &chaddr[0], &chaddr[1], &chaddr[2], &chaddr[3], &chaddr[4], &chaddr[5]) != 6) {
		EXIT();
		return 1;
	}

	memset(mask, 0xff, sizeof(mask));
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.ChaddrMask */
	s = tr069_get_string_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_ChaddrMask);
	if (s && *s != '\0') {
		if (sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
			   &mask[0], &mask[1], &mask[2], &mask[3], &mask[4], &mask[5]) != 6) {
			EXIT();
			return 1;
		}
	}

	for (int i = 0; i < 6; i++)
		verdict &= ((chaddr[i] & mask[i]) == (req->request->chaddr[i] & mask[i]));

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.ChaddrExclude */
	if (tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_ChaddrExclude))
		verdict = !verdict;

	return verdict;
}

static int ip_is_in_pool(struct tr069_value_table *dhcpt, struct in_addr ip)
{
	tr069_id poffs = 0;
	struct in_addr min;
	struct in_addr mask;

	if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool)
		poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MinAddress */
	min = tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_MinAddress);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.SubnetMask */
	mask = tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_SubnetMask);

	return in_same_network(min, ip, mask);
}

/* given a LANDevice and an DHCP request, find the best matching DHCPConditionalServingPool */
static struct tr069_value_table *find_dhcpcspool(struct tr069_value_table *lhcm, struct dhcp_req *req, struct in_addr sel_ip)
{
	struct tr069_instance *dhcps;
	struct tr069_instance_node *node;

	ENTER();

	dhcps = tr069_get_instance_ref_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool);
	if (!dhcps) {
		EXIT();
		return lhcm;
	}

	/* process DHCPConditionalServingPools in PoolOrder */
        for (node = tr069_instance_last_idx(dhcps, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder);
             node != NULL;
             node = tr069_instance_prev_idx(dhcps, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_PoolOrder, node)) {
		struct tr069_value_table *dhcpt = DM_TABLE(node->table);

		debug(": testing pool: %d", node->instance);

		if (!tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_Enable)) {
			debug("pool not enabled");
			continue;
		}

		if (sel_ip.s_addr != INADDR_ANY) {
			/* take selector IP into account */

			if (!ip_is_in_pool(dhcpt, sel_ip))
				continue;
		}

		/* FIXME: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.SourceInterface */

		if (match_vendorid(dhcpt, req) &&
		    match_clientid(dhcpt, req) &&
		    match_userclassid(dhcpt, req) &&
		    match_chaddr(dhcpt, req)) {
			EXIT_MSG(": selected pool %d", node->instance);
			return dhcpt;
		}
	}

	EXIT_MSG(": selected root pool");
	return lhcm;
}

static void do_log_request(const char *type, struct dhcp_req *req, const char *ip)
{
	struct dhcp_opt *hname = NULL;

	if (req->host_name)
		hname = OPT_PTR(req->request, req->host_name);

	logx(LOG_EV | LOG_INFO, "%s %s %02x:%02x:%02x:%02x:%02x:%02x %.*s", type, ip,
	     req->request->chaddr[0], req->request->chaddr[1], req->request->chaddr[2],
	     req->request->chaddr[3], req->request->chaddr[4], req->request->chaddr[5],
	     hname ? hname->len : 0, hname ? (char *)&hname->data : "");
}


static void log_request(const char *type, struct dhcp_req *req)
{
	char ip[INET6_ADDRSTRLEN] = "-";

	if (req->req_ip) {
		struct dhcp_opt *opt;

		opt = OPT_PTR(req->request, req->req_ip);
		inet_ntop(AF_INET, (struct in_addr *)opt->data, ip, INET_ADDRSTRLEN);
	} else if (req->request->yiaddr.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &req->request->yiaddr, ip, INET_ADDRSTRLEN);
	} else if (req->request->ciaddr.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &req->request->ciaddr, ip, INET_ADDRSTRLEN);
	}

	do_log_request(type, req, ip);
}


static void log_reply(const char *type, struct dhcp_req *req)
{
	char ip[INET6_ADDRSTRLEN] = "-";

	if (req->answer->yiaddr.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &req->answer->yiaddr, ip, INET_ADDRSTRLEN);
	} else if (req->req_ip) {
		struct dhcp_opt *opt;

		opt = OPT_PTR(req->request, req->req_ip);
		inet_ntop(AF_INET, (struct in_addr *)opt->data, ip, INET_ADDRSTRLEN);
	} else if (req->request->ciaddr.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &req->answer->ciaddr, ip, INET_ADDRSTRLEN);
	}

	do_log_request(type, req, ip);
}

static int do_discover(struct tr069_value_table *land, const tr069_selector l2dev, struct dhcp_req *req)
{
	struct tr069_value_table *lhcm;
	struct tr069_value_table *dhcpt;
	struct tr069_instance_node *host;
	struct tr069_value_table *slease;
	struct in_addr ipaddr;
	tr069_selector *sel;
	struct dhcp_opt *opt;
	int host_updated = 0;

	ENTER();

	log_request("DHCPDISCOVER", req);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
	lhcm = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_LANHostConfigManagement);
	if (!lhcm) {
		EXIT();
		return 0;
	}

	/* find DHCP pool */
	if (req->request->giaddr.s_addr != INADDR_ANY)
		dhcpt = find_dhcpcspool(lhcm, req, req->request->giaddr);
	else
		dhcpt = find_dhcpcspool(lhcm, req, req->laddr);

	slease = get_static_lease_by_chaddr(dhcpt, req->request->chaddr);
	host = get_host_by_id(land, req);

	if (host && slease) {
		/** InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Yiaddr */
		ipaddr = tr069_get_ipv4_by_id(slease, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Yiaddr);
		if (ipaddr.s_addr != tr069_get_ipv4_by_id(DM_TABLE(host->table),
							  cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress).s_addr) {
			/* new static lease for host, remove old lease */
			remove_lease(DM_TABLE(host->table));
			host = NULL;
		}
	}

	if (host) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPPool */
		sel = tr069_get_selector_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPPool);
		if (sel && tr069_selcmp(*sel, dhcpt->id, TR069_SELECTOR_LEN) != 0) {
			/* host switched networks, remove lease */
			remove_lease(DM_TABLE(host->table));
			host = NULL;
		}
	}

	if (!host) {
		host = add_lease_host(land, l2dev, req);
		host_updated = 1;
	} else
		/* update exising host entry */
		update_lease_host(DM_TABLE(host->table), l2dev, req);

	if (!host) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
	tr069_set_enum_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource, cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_DHCP);

	if (slease) {
		struct tr069_instance_node *lease;

		/** InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPStaticAddress.{i}.Yiaddr */
		ipaddr = tr069_get_ipv4_by_id(slease, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Yiaddr);

		/* check if the IP has been taken */
		lease = get_host_by_ip(land, ipaddr);
		if (lease && lease != host) {
			/* we have a (possibly brand new) static lease, but it is taken */
			ipaddr = (struct in_addr){ .s_addr = INADDR_ANY };
		} else {
			alloc_ipaddr(dhcpt, ipaddr);
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
			tr069_set_enum_by_id(DM_TABLE(host->table),
					     cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource,
					     cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_Static);
		}
	} else
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
		ipaddr = tr069_get_ipv4_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress);

	if (ipaddr.s_addr == INADDR_ANY || ipaddr.s_addr == INADDR_NONE) {
		int need_alloc = 1;

		if (req->req_ip) {
			/* check if the request IP is available */
			opt = OPT_PTR(req->request, req->req_ip);
			ipaddr = *(struct in_addr *)opt->data;

			if (ipaddr.s_addr != INADDR_ANY &&
			    ip_is_in_pool(dhcpt, ipaddr)) {
				    if (!get_static_lease_by_ip(dhcpt, ipaddr)) {
					    /* try to alloc */
					    need_alloc = (try_alloc_dhcp_addr(dhcpt, ipaddr) == 0);
					    if (need_alloc) {
						    /* address is taken, check if the lease has expired */

						    struct tr069_instance_node *lease;

						    lease = get_host_by_ip(land, ipaddr);
						    if (lease && lease != host) {
							    time_t expire;

							    expire = tr069_get_int_by_id(DM_TABLE(lease->table),
											 cwmp__IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining);
							    if (expire < monotonic_time()) {
								    remove_lease(DM_TABLE(lease->table));
								    need_alloc = (try_alloc_dhcp_addr(dhcpt, ipaddr) == 0);
							    }
						    }
					    }
				    }
			}
		}

		if (need_alloc && !alloc_dhcp_addr(dhcpt, req->request->chaddr, &ipaddr)) {
			EXIT();
			return 0;
		}
		host_updated = 1;
	}

	if (host_updated) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
		tr069_set_ipv4_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, ipaddr);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPPool */
		tr069_set_selector_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPPool, dhcpt->id);

		update_instance_node_index(host);
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_State */
	tr069_set_enum_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State, cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_DHCPOffered);

	prepare_reply(req);
	req->answer->ciaddr = (struct in_addr){ .s_addr = INADDR_ANY };
	req->answer->yiaddr = ipaddr;
	req->answer->siaddr = get_primary_ip(land);

	add_opt_uint8(req->answer, &req->repl_len, OPT_MESSAGE_TYPE, DHCPOFFER);
	add_opt_uint32(req->answer, &req->repl_len, OPT_SERVER_IDENTIFIER, req->answer->siaddr.s_addr);

	add_lease_time_option(dhcpt, DM_TABLE(host->table), req);
	add_lease_options(dhcpt, ipaddr, req);

	add_opt_raw(req->answer, &req->repl_len, OPT_END, 0, NULL);

	log_reply("DHCPOFFER", req);

	EXIT();
	return 1;
}

static int return_ACK(struct tr069_value_table *dhcpt, struct tr069_value_table *host, struct dhcp_req *req, struct in_addr ipaddr)
{
	ENTER();

	log_reply("DHCPACK", req);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
	tr069_set_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource, cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_DHCP);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_State */
	tr069_set_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State, cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_Active);

	add_opt_uint8(req->answer, &req->repl_len, OPT_MESSAGE_TYPE, DHCPACK);
	add_opt_uint32(req->answer, &req->repl_len, OPT_SERVER_IDENTIFIER, req->answer->siaddr.s_addr);

	add_lease_time_option(dhcpt, host, req);
	add_lease_options(dhcpt, ipaddr, req);

	add_opt_raw(req->answer, &req->repl_len, OPT_END, 0, NULL);

	req->answer->ciaddr = req->request->ciaddr;
	req->answer->yiaddr = ipaddr;

	hs_update_client_by_device(
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Layer2Interface */
		*tr069_get_selector_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_Layer2Interface),
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
		tr069_get_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource) + 1,
		ipaddr,
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.MACAddress */
		tr069_get_string_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_MACAddress),
		NULL, NULL, NULL,
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentCircuitId */
		tr069_get_binary_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentCircuitId),
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_AgentRemoteId */
		tr069_get_binary_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_AgentRemoteId),
		host->id,
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.LeaseTimeRemaining */
		time2ticks(tr069_get_int_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_LeaseTimeRemaining)));

	EXIT();
	return 1;
}

static int return_NAK(struct tr069_value_table *land, struct dhcp_req *req, const char *msg)
{
	ENTER();

	log_reply("DHCPNAK", req);

	add_opt_uint8(req->answer, &req->repl_len, OPT_MESSAGE_TYPE, DHCPNAK);
	add_opt_uint32(req->answer, &req->repl_len, OPT_SERVER_IDENTIFIER, req->answer->siaddr.s_addr);
	add_opt_raw(req->answer, &req->repl_len, OPT_MESSAGE, strlen(msg), msg);

	add_opt_raw(req->answer, &req->repl_len, OPT_END, 0, NULL);

	/* a NAK for a client that
	 *   - thinks it has an IP
	 *   - the IP is not local
	 *   - not an AutoConfig IP  169.254.0.0/16
	 */
	if (!(req->flags & F_BROADCAST) &&
	    (req->request->ciaddr.s_addr == INADDR_ANY ||
	    is_local_ip(land, req->request->ciaddr) ||
	     (ntohl(req->request->ciaddr.s_addr) & IN_CLASSB_NET) == 0xa9fe0000))
	    req->flags |= F_BROADCAST;

	req->answer->ciaddr = (struct in_addr){ .s_addr = INADDR_ANY };
	req->answer->yiaddr = (struct in_addr){ .s_addr = INADDR_ANY };
	req->answer->siaddr = (struct in_addr){ .s_addr = INADDR_ANY };

	req->answer->flags |= htons(0x8000);

	EXIT();
	return 1;
}

static int do_request(struct tr069_value_table *land, const tr069_selector l2dev, struct dhcp_req *req)
{
	struct tr069_value_table *dhcpt = NULL;
	struct tr069_instance_node *host;
	struct in_addr ipaddr    = { .s_addr = INADDR_ANY };
	struct in_addr req_ip    = { .s_addr = INADDR_ANY };
	struct in_addr server_id = { .s_addr = INADDR_ANY };
	struct in_addr my_id;
	struct dhcp_opt *opt;

	ENTER();

	log_request("DHCPREQUEST", req);

	host = get_host_by_id(land, req);

	prepare_reply(req);

	my_id = get_primary_ip(land);
	req->answer->siaddr = my_id;

	if (host) {
		tr069_selector *sel;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
		ipaddr = tr069_get_ipv4_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress);

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPPool */
		sel = tr069_get_selector_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPPool);
		if (!sel) {
			EXIT();
			return return_NAK(land, req, "no leases available");
		}

		dhcpt = tr069_get_table_by_selector(*sel);
		if (!dhcpt) {
			EXIT();
			return return_NAK(land, req, "no leases available");
		}
	}

	if (req->req_ip) {
		opt = OPT_PTR(req->request, req->req_ip);
		req_ip = *(struct in_addr *)opt->data;
	}
	if (req->server_id) {
		opt = OPT_PTR(req->request, req->server_id);
		server_id = *(struct in_addr *)opt->data;
	}

	if (req->req_ip) {
		/* SELECTING or INIT-REBOOT */

		if (req->server_id) {
			/* SELECTING */
			debug(": SELECTING");

			/* if a lease exists for this host and another address, remove it. */
			if (host && ipaddr.s_addr != req_ip.s_addr) {
				remove_lease(DM_TABLE(host->table));
				host = NULL;
			}

			if (my_id.s_addr != server_id.s_addr) {
				EXIT();
				return return_NAK(land, req, "wrong server-ID");
			}
		} else {
			/* INIT-REBOOT */
			debug(": INIT-REBOOT");

			if (host && ipaddr.s_addr != req_ip.s_addr) {
				remove_lease(DM_TABLE(host->table));
				EXIT();
				return return_NAK(land, req, "wrong address");
			}
		}
	} else {
		/* RENEWING or REBINDING */
		debug(": RENEWING or REBINDING");

		if (host && ipaddr.s_addr != req->request->ciaddr.s_addr) {
			EXIT();
			/* FIXME: force broadcast */
			return return_NAK(land, req, "lease not found");
		}

		req_ip = req->request->ciaddr;
	}

	/* try to recover from a lost lease database */
	if (!host) {
		struct tr069_value_table *lhcm;
		struct tr069_value_table *slease;

		/* FIXME: add CondServingPool selection */

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
		lhcm = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_LANHostConfigManagement);
		if (!lhcm) {
			EXIT();
			return return_NAK(NULL, req, "no leases available");
		}

		/* find DHCP pool */
		if (req->request->giaddr.s_addr != INADDR_ANY)
			dhcpt = find_dhcpcspool(lhcm, req, req->request->giaddr);
		else
			dhcpt = find_dhcpcspool(lhcm, req, req->laddr);

		slease = get_static_lease_by_chaddr(dhcpt, req->request->chaddr);
		if (slease) {
			struct tr069_instance_node *lease;

			/* validate static lease vs. requested IP */
			ipaddr = tr069_get_ipv4_by_id(slease, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPStatic_j_Yiaddr);
			if (ipaddr.s_addr != req_ip.s_addr) {
				/* a new static lease has been configured */
				EXIT();
				return return_NAK(land, req, "new static lease available");
			}

			lease = get_host_by_ip(land, req_ip);
			if (lease) {
				EXIT();
				return return_NAK(land, req, "static leases already taken");
			}

			host = add_lease_host(land, l2dev, req);
			if (!host) {
				EXIT();
				return return_NAK(land, req, "no leases left");
			}

			/* mark IP as taken */
			alloc_ipaddr(dhcpt, req_ip);

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
			tr069_set_enum_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource,
					     cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_Static);
		} else {
			if (!try_alloc_dhcp_addr(dhcpt, req_ip)) {
				EXIT();
				return return_NAK(land, req, "leases already taken");
			}

			host = add_lease_host(land, l2dev, req);
			if (!host) {
				release_dhcp_addr(dhcpt, req_ip);
				EXIT();
				return return_NAK(land, req, "no leases left");
			}

			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.AddressSource */
			tr069_set_enum_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource,
					     cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_DHCP);
		}

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
		tr069_set_ipv4_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress, req_ip);
		ipaddr = req_ip;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_DHCPPool */
		tr069_set_selector_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPPool, dhcpt->id);

		update_instance_node_index(host);

		/*
		 * force IP's from remote networks through the relay agent
		 *
		 * the IP has already be reserved, this makes sure that the host gets it's old IP and
		 * that we are not giving out IP's that are taken but that we have yet seen again
		 */
		if (req->request->giaddr.s_addr == INADDR_ANY &&
		    !is_local_ip(land, req_ip)) {
			/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_TPBS_State */
			tr069_set_enum_by_id(DM_TABLE(host->table),
					     cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State,
					     cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_DHCPOffered);

			EXIT();
			return return_NAK(land, req, "need to rediscover non local lease");
		}
	} else {
		tr069_id poffs = 0;
		struct in_addr netmask;
		struct in_addr min;

		/* check DHCPConditionalServingPool association */

		if (dhcpt->id[4] == cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool) {
			if (!tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_Enable)) {
				/* ignore DHCPREQUEST for disabled pool */
				EXIT();
				return 0;
			}
			poffs = abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo - cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
		}

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MinAddress */
		min = tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_MinAddress);
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.SubnetMask */
		netmask = tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_SubnetMask);

		if (!in_same_network(min, ipaddr, netmask) ||
		    (req->request->giaddr.s_addr != INADDR_ANY &&
		     !in_same_network(req->request->giaddr, ipaddr, netmask))) {
			/* client has switched networks */
			EXIT();
			return return_NAK(land, req, "wrong network");
		}
	}

	EXIT();
	return return_ACK(dhcpt, DM_TABLE(host->table), req, ipaddr);
}

static int do_inform(struct tr069_value_table *land, const tr069_selector l2dev, struct dhcp_req *req)
{
	struct tr069_value_table *lhcm;
	struct tr069_value_table *dhcpt;

	ENTER();

	log_request("DHCPINFORM", req);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
	lhcm = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_LANHostConfigManagement);
	if (!lhcm) {
		EXIT();
		return 0;
	}

	/* find DHCP pool */
	dhcpt = find_dhcpcspool(lhcm, req, req->request->ciaddr);

	prepare_reply(req);

	req->answer->siaddr = get_primary_ip(land);

	add_opt_uint8(req->answer, &req->repl_len, OPT_MESSAGE_TYPE, DHCPACK);
	add_opt_uint32(req->answer, &req->repl_len, OPT_SERVER_IDENTIFIER, req->answer->siaddr.s_addr);

	add_lease_options(dhcpt, req->request->ciaddr, req);

	add_opt_raw(req->answer, &req->repl_len, OPT_END, 0, NULL);

	req->answer->ciaddr = req->request->ciaddr;
	req->answer->yiaddr = (struct in_addr){ .s_addr = INADDR_ANY };

	EXIT();
	return 1;
}

static int do_release(struct tr069_value_table *land, const tr069_selector l2dev, struct dhcp_req *req)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	tr069_selector *sel;
	struct tr069_instance_node *host;
	struct in_addr ipaddr;
	struct in_addr req_ip;
	struct in_addr my_id;
	struct in_addr server_id = { .s_addr = INADDR_ANY };
	struct dhcp_opt *opt;

	ENTER();

	host = get_host_by_id(land, req);
	if (!host) {
		debug(": got %s for unknown host", req->message_type == DHCPRELEASE ? "DHCPRELEASE" : "DHCPDECLINE");
		EXIT();
		return 0;
	}

	if (req->message_type == DHCPRELEASE)
		req_ip = req->request->ciaddr;
	else {
		if (!req->req_ip) {
			debug(": got DHCPDECLINE without IP");
			EXIT();
			return 0;
		}
		opt = OPT_PTR(req->request, req->req_ip);
		req_ip = *(struct in_addr *)opt->data;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
	ipaddr = tr069_get_ipv4_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress);
	if (ipaddr.s_addr == INADDR_ANY ||
	    ipaddr.s_addr != req_ip.s_addr) {
		debug(": got %s for wrong IP", req->message_type == DHCPRELEASE ? "DHCPRELEASE" : "DHCPDECLINE");
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Layer2Interface */
	sel = tr069_get_selector_by_id(DM_TABLE(host->table), cwmp__IGD_LANDev_i_Hosts_H_j_Layer2Interface);
	if (!sel || tr069_selcmp(l2dev, *sel, TR069_SELECTOR_LEN) != 0) {
		debug(": got %s on invalid interface, expected: %s",
		      req->message_type == DHCPRELEASE ? "DHCPRELEASE" : "DHCPDECLINE",
		      sel ? sel2str(b1, *sel) : "NULL" );
		EXIT();
		return 0;
	}

	my_id = get_primary_ip(land);
	if (req->server_id) {
		opt = OPT_PTR(req->request, req->server_id);
		server_id = *(struct in_addr *)opt->data;
	}

	if (server_id.s_addr == INADDR_ANY ||
	    server_id.s_addr != my_id.s_addr) {
		debug(": got %s with wrong server id", req->message_type == DHCPRELEASE ? "DHCPRELEASE" : "DHCPDECLINE");
		EXIT();
		return 0;
	}

	remove_lease(DM_TABLE(host->table));

	EXIT();
	return 0;
}

static int validate_pkt(struct dhcp_packet *pkt, size_t pkt_len)
{
	if (pkt_len < sizeof(struct dhcp_packet))
		return 0;

	if (pkt->op != BOOTREQUEST)
		return 0;

	if (pkt->htype != 1 && pkt->hlen != 6)
		/* only Ethernet is supported */
		return 0;

	return 1;
}

#define OPT_OFFS(req, opt) (((uint8_t *)opt) - ((uint8_t *)req))
#define OPT_INCR(opt, inc) ((struct dhcp_opt *)(((uint8_t *)opt) + inc))

static void decode_agent_id(struct dhcp_req *req, struct dhcp_opt *opt)
{
	struct dhcp_opt *sopt;

	sopt = (struct dhcp_opt *)&opt->data;
	while ((uint8_t *)sopt < ((uint8_t *)opt->data) + opt->len) {
		switch (sopt->op) {
		case AGENT_OPT_CIRCUIT_ID:
			req->agent_circuit_id = OPT_OFFS(req->request, sopt);
			break;

		case AGENT_OPT_REMOTE_ID:
			req->agent_remote_id = OPT_OFFS(req->request, sopt);
			break;

		case AGENT_OPT_SUBSCRIBER_ID:
			req->agent_subscriber_id = OPT_OFFS(req->request, sopt);
			break;

		case AGENT_OPT_SERVER_ID_OVERRIDE:
			req->agent_server_id_override = OPT_OFFS(req->request, sopt);
			break;

		default:
			break;
		}
		sopt = OPT_INCR(sopt, sopt->len + 2);
	}
}

static void decode_req(struct dhcp_req *req)
{
	struct dhcp_opt *opt;

	opt = (struct dhcp_opt *)&req->request->options;

	if (*(uint32_t *)opt == DHCP_COOKIE) {
		req->flags |= F_DHCPREQ;
		opt = OPT_INCR(opt, 4);
	}

	while ((uint8_t *)opt < ((uint8_t *)req->request) + req->req_len && opt->op != OPT_END) {

		req->opt_list[req->opt_list_len++] = opt->op;

		switch (opt->op) {
		case OPT_HOSTNAME:
			req->host_name = OPT_OFFS(req->request, opt);
			break;

		case OPT_REQUESTED_IP:
			req->req_ip = OPT_OFFS(req->request, opt);
			break;

		case OPT_MESSAGE_TYPE:
			req->message_type = opt->data[0];
			break;

		case OPT_REQUESTED_OPTS:
			req->sopt_req_list_len = opt->len;
			memcpy(req->sopt_req_list, opt->data, opt->len);
			qsort(req->sopt_req_list, req->sopt_req_list_len, 1, cmp_byte);
			req->opt_req_list = OPT_OFFS(req->request, opt);
			break;

		case OPT_SERVER_IDENTIFIER:
			req->server_id = OPT_OFFS(req->request, opt);
			break;

		case OPT_VENDOR_ID:
			req->vendor_id = OPT_OFFS(req->request, opt);
			break;

		case OPT_CLIENT_ID:
			req->client_id = OPT_OFFS(req->request, opt);
			break;

		case OPT_USER_CLASS:
			req->user_class = OPT_OFFS(req->request, opt);
			break;

		case OPT_CLIENT_FQDN:
			req->client_fqdn = OPT_OFFS(req->request, opt);
			break;

		case OPT_AGENT_ID:
			req->agent_id = OPT_OFFS(req->request, opt);
			decode_agent_id(req, opt);
			break;

		case OPT_AUTO_CONFIGURE:
			req->flags |= F_DHCP_AUTOCFG;
			break;

		default:
			break;
		}
		opt = OPT_INCR(opt, opt->len + 2);
	}
}

static int process_req(struct tr069_value_table *land, const tr069_selector l2dev, struct dhcp_req *req)
{
	int rc = 0;

	ENTER();

	decode_req(req);

	switch (req->message_type) {
	case DHCPDISCOVER:
		rc = do_discover(land, l2dev, req);
		break;

	case DHCPREQUEST:
		rc = do_request(land, l2dev, req);
		break;

	case DHCPINFORM:
		rc = do_inform(land, l2dev, req);
		break;

	case DHCPRELEASE:
	case DHCPDECLINE:
		rc = do_release(land, l2dev, req);
		break;

	default:
		debug(": unsupported DHCP request type: %d", req->message_type);
		break;
	}

	EXIT();
	return rc;
}

static void dhcpsrv_ev_cb(EV_P_ ev_io *w, int revents)
{
#if defined(SDEBUG)
	char b1[128];
	char ip[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
#endif
	struct tr069_instance *devi;
	struct tr069_instance_node *dev;
	tr069_selector *sel;
	struct tr069_value_table *land;
	uint8_t req_buf[4069];
	uint8_t repl_buf[DHCP_MAX_REPLY_LEN];
	struct iovec iov = {
		.iov_base = req_buf,
		.iov_len  = sizeof(req_buf),
	};
	struct dhcp_req req = {
		.request = (struct dhcp_packet *)req_buf,

		.repl_len = sizeof(struct dhcp_packet),
		.answer = (struct dhcp_packet *)repl_buf,
	};
	struct sockaddr_in daddr;
	int if_idx = -1;
	static struct ifreq ifr = {
		.ifr_ifindex = -1,
	};
	int rc;

	char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct cmsghdr *cmsg;

	struct msghdr msg = {
		.msg_name = &daddr,
		.msg_namelen = sizeof(daddr),

		.msg_iov = &iov,
		.msg_iovlen = 1,

		.msg_controllen = sizeof(cbuf),
		.msg_control    = &cbuf,
		.msg_flags = 0,
	};

	ENTER();

	debug(": event: %x, fd: %d", revents, w->fd);

	rc = recvmsg(w->fd, &msg, 0);
	if (rc < 0) {
		debug(": recvmsg rc: %d (%m)", rc);
		EXIT();
		return;
	}

	if (!validate_pkt((struct dhcp_packet *)req_buf, rc)) {
		EXIT();
		return;
	}
	req.req_len = rc;

	debug(": rc: %d", rc);
	debug(": msg_name: %s", ip2str(daddr.sin_addr, ip));
	debug(": iov_len: %d", iov.iov_len);
	debug(": msg_controllen: %d", msg.msg_controllen);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		debug(": cmsg: level: %d, type: %d", cmsg->cmsg_level, cmsg->cmsg_type);

		if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pktinfo;

			pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
			if_idx = pktinfo->ipi_ifindex;
			req.laddr = pktinfo->ipi_spec_dst;
			debug(": pktinfo: ifindex: %d, addr: %s, spec_dst: %s",
			      pktinfo->ipi_ifindex, ip2str(pktinfo->ipi_addr, ip), ip2str(pktinfo->ipi_spec_dst, dst));

		}
	}
	debug(": msg_flags: %x", msg.msg_flags);

	if (if_idx < 0) {
		EXIT();
		return;
	}
	if (ifr.ifr_ifindex != if_idx) {
		ifr.ifr_ifindex = if_idx;
		if (ioctl(w->fd, SIOCGIFNAME, &ifr) < 0) {
			EXIT();
			return;
		}
	}
	debug(": ifr_name: %s", ifr.ifr_name);

	devi = get_if_layout(ifr.ifr_name);
	if (!devi) {
		EXIT();
		return;
	}

	sel = NULL;
	for (dev = tr069_instance_first(devi);
	     dev != NULL;
	     dev = tr069_instance_next(devi, dev))
	{
		tr069_selector *dref;

		/** VAR: InternetGatewayDevice.X_TPOSS_InterfaceMap.Interface.{i}.Device.{i}.DeviceReference */
		dref = tr069_get_selector_by_id(DM_TABLE(dev->table), cwmp__IGD_IfMap_If_i_Dev_j_DeviceReference);
		if (dref && (!sel || tr069_sellen(*sel) <= tr069_sellen(*dref)))
			sel = dref;
	}
	if (!sel) {
		EXIT();
		return;
	}
	debug(": sel: %s", sel2str(b1, *sel));
	if ((*sel)[1] != cwmp__IGD_LANDevice ||
	    (*sel)[2] == 0) {
		EXIT();
		return;
	}
	land = tr069_get_table_by_selector((tr069_selector){cwmp__InternetGatewayDevice,
				cwmp__IGD_LANDevice,
				(*sel)[2], 0});
	debug(": land: %p, id: %s", land, land ? sel2str(b1, land->id) : "NULL");
	if (!land) {
		EXIT();
		return;
	}

	/* force broadcast replies if the client wishes so */
	if (ntohs(req.request->flags) & 0x8000)
		req.flags |= F_BROADCAST;

	/* clear the answer buffer */
	memset(repl_buf, 0, sizeof(repl_buf));

	if (!process_req(land, *sel, &req)) {
		EXIT();
		return;
	}

	/* msg_name and msg_namelen take from recvmsg */
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	iov.iov_base = req.answer;
	iov.iov_len = req.repl_len;

	debug(": giaddr: %s", ip2str(req.answer->giaddr, ip));
	debug(": ciaddr: %s", ip2str(req.answer->ciaddr, ip));
	debug(": flags: %02x", req.flags);
	debug(": yiaddr: %s", ip2str(req.answer->yiaddr, ip));

	if (req.answer->giaddr.s_addr != INADDR_ANY) {
		/* send to relay  */
		debug(": send answer to relay %s", ip2str(req.answer->giaddr, ip));

		daddr.sin_port = htons(67);
		daddr.sin_addr = req.answer->giaddr;
	}
	else if (req.answer->ciaddr.s_addr != INADDR_ANY) {
		if ((req.message_type != DHCPINFORM &&
		     daddr.sin_addr.s_addr != req.answer->ciaddr.s_addr) ||
		    daddr.sin_port == 0 ||
		    daddr.sin_addr.s_addr == INADDR_ANY)
		{
			daddr.sin_port = htons(68);
			daddr.sin_addr = req.answer->ciaddr;
		}
		debug(": send answer to configured client %s", ip2str(daddr.sin_addr, ip));
	}
	else if (req.flags & F_BROADCAST) {
		debug(": broadcast answer");
		/* broadcast to 255.255.255.255 */

		struct in_pktinfo *pkt;

		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		cmsg = CMSG_FIRSTHDR(&msg);

		pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
		pkt->ipi_ifindex = if_idx;
		pkt->ipi_spec_dst.s_addr = INADDR_ANY;

		msg.msg_controllen = cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

		cmsg->cmsg_level = SOL_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		daddr.sin_addr.s_addr = INADDR_BROADCAST;
		daddr.sin_port = htons(68);
	} else if (req.answer->yiaddr.s_addr != INADDR_ANY) {
		debug(": unicast answer %s", ip2str(req.answer->yiaddr, ip));

		/* unicast to unconfigured client
		 * inject MAC address direct into ARP cache */
		struct arpreq arp;

		daddr.sin_addr = req.answer->yiaddr;
		daddr.sin_port = htons(68);

		*((struct sockaddr_in *)&arp.arp_pa) = daddr;

		arp.arp_ha.sa_family = req.answer->htype;
		memcpy(arp.arp_ha.sa_data, req.answer->chaddr, req.answer->hlen);
		strncpy(arp.arp_dev, ifr.ifr_name, 16);
		arp.arp_flags = ATF_COM;
		ioctl(w->fd, SIOCSARP, &arp);
	} else
		debug(": reply to source IP");

	/*
	 * if nothing matched, reply to soure IP
	 */

	rc = sendmsg(w->fd, &msg, 0);
	if (rc < 0)
		debug(": rc: %d (%m)", rc);

	EXIT();
}

static ev_io dhcp_srvev;

static void dhcp_init(void)
{
	int sk;
	struct sockaddr_in saddr;
	int opt = 1;
	int mtu = IP_PMTUDISC_DONT;
	int rc;

	ENTER();

	sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0) {
		EXIT();
		return;
	}

	fcntl(sk, F_SETFD, FD_CLOEXEC | fcntl(sk, F_GETFD));
	fcntl(sk, F_SETFL, O_NONBLOCK);

	setsockopt(sk, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
	setsockopt(sk, SOL_IP, IP_PKTINFO, &opt, sizeof(opt));
	setsockopt(sk, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(67);
	saddr.sin_addr.s_addr = INADDR_ANY;

	rc = bind(sk, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (rc < 0) {
		debug(": rc: %d (%m)", rc);
		close(sk);
		EXIT();
		return;
	}

	ev_io_init(&dhcp_srvev, dhcpsrv_ev_cb, sk, EV_READ);
	ev_io_start(EV_DEFAULT_ &dhcp_srvev);

	EXIT();
}

void del_IGD_LANDev_i_Hosts_Host(const struct tr069_table *kw __attribute__ ((unused)),
				 tr069_id id __attribute__ ((unused)),
				 struct tr069_instance *inst __attribute__ ((unused)),
				 struct tr069_instance_node *node)
{
	struct tr069_value_table *host = DM_TABLE(node->table);
	struct host_info *hi;

	ENTER();

	if (tr069_get_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_AddressSource) == cwmp___IGD_LANDev_i_Hosts_H_j_AddressSource_DHCP &&
	    tr069_get_enum_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_State) != cwmp___IGD_LANDev_i_Hosts_H_j_X_TPBS_State_Invalid)
	{
		tr069_selector *sel;

		/* only DHCP leases that are not invalid can be released */
		sel = tr069_get_selector_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_TPBS_DHCPPool);
		if (sel) {
			struct tr069_value_table *dhcpt;

			dhcpt = tr069_get_table_by_selector(*sel);
			if (dhcpt)
				release_dhcp_addr(dhcpt, tr069_get_ipv4_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress));
		}
	}

	hs_remove_client_by_device(
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.Layer2Interface */
		*tr069_get_selector_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_Layer2Interface),
		/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.IPAddress */
		tr069_get_ipv4_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_IPAddress),
		0);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.Hosts.Host.{i}.X_DM_HostInfo */
	hi = tr069_get_ptr_by_id(host, cwmp__IGD_LANDev_i_Hosts_H_j_X_DM_HostInfo);
	if (hi) {
		ev_timer_stop(EV_DEFAULT_ &hi->timer);
		free(hi);
	}

	EXIT();
}

/* given a LANDevice and an IP address, find the ip_pool this IP would fall into */
static struct network_pool *find_dhcp_pool(struct tr069_value_table *lhcm, const struct in_addr ipaddr)
{
#if defined(SDEBUG)
	char ipbuf[INET6_ADDRSTRLEN];
#endif
	uint32_t ip;
	struct tr069_instance *dhcpc;
	struct tr069_instance_node *node;
	struct ip_pool *pool;

	ENTER("(ipaddr: %s)", ip2str(ipaddr, ipbuf));

	ip = ntohl(ipaddr.s_addr);


	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.X_DM_PoolInfo */
	pool = tr069_get_ptr_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
	if (pool && ip >= pool->network->base && ip <= pool->network->base + pool->size) {
		EXIT();
		return pool->network;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool */
	dhcpc = tr069_get_instance_ref_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool);
	if (!dhcpc) {
		EXIT();
		return NULL;
	}

        for (node = tr069_instance_first(dhcpc);
             node != NULL;
             node = tr069_instance_next(dhcpc, node)) {
		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.Enable */
		if (!tr069_get_bool_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_Enable))
			continue;

		pool = tr069_get_ptr_by_id(DM_TABLE(node->table), cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo);
		if (pool && ip >= pool->network->base && ip <= pool->network->base + pool->size) {
			EXIT();
			return pool->network;
		}
	}

	return NULL;
}

static struct network_pool *new_dhcp_network_pool(uint32_t min, uint32_t mask)
{
	struct network_pool *network;
	uint32_t size;
	uint32_t base;

	ENTER();

	base = min & mask;
	/* /16 is the maximum poll size */
	if (mask < 0xffff0000) {
		EXIT();
		return NULL;
	}

	size = (~mask) + 1;
	network = new_network_pool(base, size);
	if (!network) {
		EXIT();
		return NULL;
	}

	prealloc_netaddr(network);

	EXIT();
	return network;
}

static struct ip_pool *new_dhcp_ip_pool(struct tr069_value_table *dhcpt, tr069_id poffs, struct network_pool *network)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct ip_pool *pool;
	uint32_t min;
	uint32_t max;
	uint32_t mask;

	ENTER("(dhcpt: %s)", sel2str(b1, dhcpt->id));

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MinAddress */
	min = ntohl(tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_MinAddress).s_addr);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.MaxAddress */
	max = ntohl(tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_MaxAddress).s_addr);
	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.SubnetMask */
	mask = ntohl(tr069_get_ipv4_by_id(dhcpt, poffs + cwmp__IGD_LANDev_i_HostCfgMgt_SubnetMask).s_addr);

	if (min > max) {
		EXIT();
		return NULL;
	}

	if (!network)
		network = new_dhcp_network_pool(min, mask);
	if (!network) {
		EXIT();
		return NULL;
	}

	pool = new_ip_pool(network, min, max);
	if (!pool) {
		EXIT();
		return NULL;
	}

	prealloc_static_addrs(dhcpt, pool);

	EXIT();
	return pool;
}

static int init_dhcp_land(const tr069_selector sel)
{
#if defined(SDEBUG)
	char b1[128];
#endif
	struct tr069_value_table *land;
	struct tr069_value_table *lhcm;
	struct tr069_instance *dhcpc;
	struct tr069_instance_node *node;
	struct ip_pool *pool;

	ENTER("(sel: %s)", sel2str(b1, sel));

	land = tr069_get_table_by_selector(sel);
	if (!land) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement */
	lhcm = tr069_get_table_by_id(land, cwmp__IGD_LANDev_i_LANHostConfigManagement);
	if (!lhcm) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPServerEnable */
	if (!tr069_get_bool_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPServerEnable)) {
		EXIT();
		return 1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPRelay */
	if (tr069_get_bool_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPRelay)) {
		EXIT();
		return 1;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.X_DM_PoolInfo */
	pool = tr069_get_ptr_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo);
	if (pool) {
		/* already initialized */
		EXIT();
		return 1;
	}

	/* base pool */
	pool = new_dhcp_ip_pool(lhcm, 0, NULL);
	if (!pool) {
		EXIT();
		return 0;
	}

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.X_DM_PoolInfo */
	tr069_set_ptr_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo, pool);

	/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool */
	dhcpc = tr069_get_instance_ref_by_id(lhcm, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPConditionalServingPool);
	if (!dhcpc) {
		EXIT();
		return 0;
	}

        for (node = tr069_instance_first(dhcpc);
             node != NULL;
             node = tr069_instance_next(dhcpc, node)) {
		struct tr069_value_table *dhcpt = DM_TABLE(node->table);
		struct network_pool *network;

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.MinAddress */
		if (!tr069_get_bool_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_Enable))
			continue;

		/* let's check if this pool overlaps with another */
		network = find_dhcp_pool(lhcm, tr069_get_ipv4_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_MinAddress));
		pool = new_dhcp_ip_pool(dhcpt, abs(cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo -
						   cwmp__IGD_LANDev_i_HostCfgMgt_X_DM_PoolInfo),
					network);
		if (!pool) {
			EXIT();
			return 0;
		}

		/** VAR: InternetGatewayDevice.LANDevice.{i}.LANHostConfigManagement.DHCPConditionalServingPool.{i}.X_DM_PoolInfo */
		tr069_set_ptr_by_id(dhcpt, cwmp__IGD_LANDev_i_HostCfgMgt_DHCPcsPool_j_X_DM_PoolInfo, pool);
	}

	EXIT();
	return 1;
}

static int dhcp_initialized = 0;

int start_dhcpd(const char *device __attribute__ ((unused)),
		const tr069_selector sel __attribute__ ((unused)))
{
#if defined(SDEBUG)
	char b1[128];
#endif

	ENTER("(dev: %s, sel: %s)", device, sel2str(b1, sel));

	init_dhcp_land(sel);

	if (dhcp_initialized) {
		EXIT();
		return 0;
	}

	dhcp_init();
	dhcp_initialized = 1;

	EXIT();
	return 0;
}

void stop_dhcpd(const char *device __attribute__ ((unused)))
{
}

int dhcp_update_wan_ip(const char *wan, const tr069_selector sel)
{
	return 0;
}

void dm_relay_action(const tr069_selector sel __attribute__((unused)),
			     enum dm_action_type type __attribute__((unused)))
{
	ENTER();

	EXIT();
}
