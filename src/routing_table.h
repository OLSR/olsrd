/*
 * The olsr.org Optimized Link-State Routing daemon (olsrd)
 *
 * (c) by the OLSR project
 *
 * See our Git repository to find out who worked on this file
 * and thus is a copyright holder on it.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#ifndef _OLSR_ROUTING_TABLE
#define _OLSR_ROUTING_TABLE

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include "hna_set.h"
#include "link_set.h"
#include "olsr_cookie.h"
#include "common/olsrd_avl.h"
#include "common/list.h"

#define NETMASK_HOST 0xffffffff
#define NETMASK_DEFAULT 0x0

/* a composite metric is used for path selection */
struct rt_metric {
  olsr_linkcost cost;
  uint32_t hops;
};

/* a nexthop is a pointer to a gateway router plus an interface */
struct rt_nexthop {
  union olsr_ip_addr gateway;          /* gateway router */
  int iif_index;                       /* outgoing interface index */
};

/*
 * Every prefix in our RIB needs a route entry that contains
 * the nexthop of the best path as installed in the kernel FIB.
 * The route entry is the root of a rt_path tree of equal prefixes
 * originated by different routers. It also contains a shortcut
 * for accessing the best route among all contributing routes.
 */
struct rt_entry {
  struct olsr_ip_prefix rt_dst;
  struct olsrd_avl_node rt_tree_node;
  struct rt_path *rt_best;             /* shortcut to the best path */
  struct rt_nexthop rt_nexthop;        /* nexthop of FIB route */
  struct rt_metric rt_metric;          /* metric of FIB route */
  struct olsrd_avl_tree rt_path_tree;
  struct list_node rt_change_node;     /* queue for kernel FIB add/chg/del */
};

OLSRD_AVLNODE2STRUCT(rt_tree2rt, struct rt_entry, rt_tree_node);
LISTNODE2STRUCT(changelist2rt, struct rt_entry, rt_change_node);

/*
 * For every received route a rt_path is added to the RIB.
 * Depending on the results of the SPF calculation we perform a
 * best_path calculation and pick the one with the lowest etx/metric.
 * The rt_path gets first inserted into the per tc_entry prefix tree.
 * If during the SPF calculation the tc_entry becomes reachable via
 * a local nexthop it is inserted into the global RIB tree.
 */
struct rt_path {
  struct rt_entry *rtp_rt;             /* backpointer to owning route head */
  struct tc_entry *rtp_tc;             /* backpointer to owning tc entry */
  struct rt_nexthop rtp_nexthop;
  struct rt_metric rtp_metric;
  struct olsrd_avl_node rtp_tree_node;       /* global rtp node */
  union olsr_ip_addr rtp_originator;   /* originator of the route */
  struct olsrd_avl_node rtp_prefix_tree_node; /* tc entry rtp node */
  struct olsr_ip_prefix rtp_dst;       /* the prefix */
  uint32_t rtp_version;                /* for detection of outdated rt_paths */
  uint8_t rtp_origin;                  /* internal, MID or HNA */
};

OLSRD_AVLNODE2STRUCT(rtp_tree2rtp, struct rt_path, rtp_tree_node);
OLSRD_AVLNODE2STRUCT(rtp_prefix_tree2rtp, struct rt_path, rtp_prefix_tree_node);

/*
 * In olsrd we have three different route types.
 * Internal routes are generated by simple reachability
 * of a node (by means of a tc message reception).
 * MID routes result from MID messages and HNA routes
 * from a gw routers HNA anncouncements.
 */
enum olsr_rt_origin {
  OLSR_RT_ORIGIN_MIN,
  OLSR_RT_ORIGIN_INT,
  OLSR_RT_ORIGIN_MID,
  OLSR_RT_ORIGIN_HNA,
  OLSR_RT_ORIGIN_MAX
};

/*
 * OLSR_FOR_ALL_RT_ENTRIES
 *
 * macro for traversing the entire routing table.
 * it is recommended to use this because it hides all the internal
 * datastructure from the callers.
 *
 * the loop prefetches the next node in order to not loose context if
 * for example the caller wants to delete the current rt_entry.
 */
#define OLSR_FOR_ALL_RT_ENTRIES(rt) \
{ \
  struct olsrd_avl_node *rt_tree_node, *next_rt_tree_node; \
  for (rt_tree_node = olsrd_avl_walk_first(&routingtree); \
    rt_tree_node; rt_tree_node = next_rt_tree_node) { \
    next_rt_tree_node = olsrd_avl_walk_next(rt_tree_node); \
    rt = rt_tree2rt(rt_tree_node);
#define OLSR_FOR_ALL_RT_ENTRIES_END(rt) }}

/*
 * OLSR_FOR_ALL_HNA_RT_ENTRIES
 *
 * macro for traversing the entire routing table and pick only
 * HNA routes. This is not optimal - however, If the RIBs become
 * too big one day then we keep an additional per origin tree
 * in order to speed up traversal.
 * In the meantime it is recommended to use this macro because
 * it hides all the internal datastructure from the callers
 * and the core maintainers do not have to update all the plugins
 * once we decide to change the datastructures.
 */
#define OLSR_FOR_ALL_HNA_RT_ENTRIES(rt) \
{ \
  struct olsrd_avl_node *rt_tree_node, *next_rt_tree_node; \
  for (rt_tree_node = olsrd_avl_walk_first(&routingtree); \
    rt_tree_node; rt_tree_node = next_rt_tree_node) { \
    next_rt_tree_node = olsrd_avl_walk_next(rt_tree_node); \
    rt = rt_tree2rt(rt_tree_node); \
    if (rt->rt_best->rtp_origin != OLSR_RT_ORIGIN_HNA) \
      continue;
#define OLSR_FOR_ALL_HNA_RT_ENTRIES_END(rt) }}

/**
 * IPv4 <-> IPv6 wrapper
 */
union olsr_kernel_route {
  struct {
    struct sockaddr rt_dst;
    struct sockaddr rt_gateway;
    uint32_t metric;
  } v4;

  struct {
    struct in6_addr rtmsg_dst;
    struct in6_addr rtmsg_gateway;
    uint32_t rtmsg_metric;
  } v6;
};

extern struct olsrd_avl_tree routingtree;
extern unsigned int routingtree_version;
extern struct olsr_cookie_info *rt_mem_cookie;

void olsr_init_routing_table(void);

unsigned int olsr_bump_routingtree_version(void);

int olsrd_avl_comp_ipv4_prefix(const void *, const void *);
int olsrd_avl_comp_ipv6_prefix(const void *, const void *);

void olsr_rt_best(struct rt_entry *);
bool olsr_nh_change(const struct rt_nexthop *, const struct rt_nexthop *);
bool olsr_hopcount_change(const struct rt_metric *, const struct rt_metric *);
bool olsr_cmp_rt(const struct rt_entry *, const struct rt_entry *);
uint8_t olsr_fib_metric(const struct rt_metric *);

char *olsr_rt_to_string(const struct rt_entry *);
char *olsr_rtp_to_string(const struct rt_path *);
#ifndef NODEBUG
void olsr_print_routing_table(struct olsrd_avl_tree *);
#else
#define olsr_print_routing_table(x) do { } while(0)
#endif

const struct rt_nexthop *olsr_get_nh(const struct rt_entry *);

/* rt_path manipulation */
struct rt_path *olsr_insert_routing_table(union olsr_ip_addr *, int, union olsr_ip_addr *, int);
void olsr_delete_routing_table(union olsr_ip_addr *, int, union olsr_ip_addr *);
void olsr_insert_rt_path(struct rt_path *, struct tc_entry *, struct link_entry *);
void olsr_update_rt_path(struct rt_path *, struct tc_entry *, struct link_entry *);
void olsr_delete_rt_path(struct rt_path *);

struct rt_entry *olsr_lookup_routing_table(const union olsr_ip_addr *);

#endif /* _OLSR_ROUTING_TABLE */

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
