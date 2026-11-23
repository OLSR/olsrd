/*
 * Import host routes some other software put in the kernel and announce
 * them as OLSR HNAs, so addresses OLSR has no other way of learning about
 * become reachable from the OLSR side.
 *
 * The source is identified by its route protocol, ImportProto - another
 * routing daemon, a roaming or tunnel manager, or anything else that
 * installs routes under a protocol of its own. An optional ImportPrefix
 * whitelist bounds what may be announced.
 *
 * Only host routes are imported: this announces addresses, not networks,
 * so a default route or an aggregate can never turn into an HNA.
 *
 * netlink walking adapted from
 * https://olegkutkov.me/2019/03/24/getting-linux-routing-table-using-netlink/
 */

#include "olsr.h"
#include "olsr_types.h"
#include "ipcalc.h"
#include "defs.h"
#include "route_import.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

/* an imported route stands for one address, never a network */
static uint8_t
host_prefix_len(void)
{
  return olsr_cnf->ip_version == AF_INET ? 32 : 128;
}

static void
parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
  memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

  while (RTA_OK(rta, len)) {
    if (rta->rta_type <= max) {
      tb[rta->rta_type] = rta;
    }

    rta = RTA_NEXT(rta, len);
  }
}

static uint32_t
rtm_get_table(const struct rtmsg *r, struct rtattr **tb)
{
  if (tb[RTA_TABLE]) {
    return *(uint32_t *) RTA_DATA(tb[RTA_TABLE]);
  }

  return r->rtm_table;
}

/* an empty whitelist means every address of the right protocol qualifies */
static bool
prefix_wanted(const union olsr_ip_addr *prefix)
{
  const struct ip_prefix_list *entry;

  if (olsr_cnf->import_prefixes == NULL) {
    return true;
  }

  for (entry = olsr_cnf->import_prefixes; entry != NULL; entry = entry->next) {
    if (ip_in_net(prefix, &entry->net)) {
      return true;
    }
  }

  return false;
}

/* 0: import it, >0: not ours, <0: malformed */
static int
convert_route(const struct nlmsghdr *nlh, union olsr_ip_addr *prefix, uint8_t *prefix_len)
{
  struct rtmsg *r = NLMSG_DATA(nlh);
  struct rtattr *tb[RTA_MAX + 1];
  int len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r));

  if (len < 0) {
    OLSR_PRINTF(1, "route import: short netlink message\n");
    return -1;
  }

  parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);

  if (r->rtm_family != olsr_cnf->ip_version
      || r->rtm_protocol != olsr_cnf->import_proto
      || r->rtm_dst_len != host_prefix_len()
      || rtm_get_table(r, tb) != RT_TABLE_MAIN
      || !tb[RTA_DST]
      || RTA_PAYLOAD(tb[RTA_DST]) < olsr_cnf->ipsize) {
    return 1;
  }

  memset(prefix, 0, sizeof(*prefix));
  memcpy(prefix, RTA_DATA(tb[RTA_DST]), olsr_cnf->ipsize);
  *prefix_len = r->rtm_dst_len;

  if (!prefix_wanted(prefix)) {
    return 1;
  }

  return 0;
}

/*
 * The other daemon rewrites a route on every metric or nexthop change, so
 * the same address keeps arriving; without this the HNA list would grow
 * without bound.
 */
static void
import_hna_add(struct ip_prefix_list **list, const union olsr_ip_addr *net, uint8_t prefix_len)
{
  struct ipaddr_str buf;

  if (ip_prefix_list_find(*list, net, prefix_len) != NULL) {
    return;
  }

  OLSR_PRINTF(1, "route import: announcing %s/%u\n", olsr_ip_to_string(&buf, net), prefix_len);
  ip_prefix_list_add(list, net, prefix_len);
}

static void
import_hna_remove(struct ip_prefix_list **list, const union olsr_ip_addr *net, uint8_t prefix_len)
{
  struct ipaddr_str buf;

  if (!ip_prefix_list_remove(list, net, prefix_len)) {
    /* a delete for something we never took, e.g. filtered by ImportPrefix */
    return;
  }

  OLSR_PRINTF(1, "route import: withdrawing %s/%u\n", olsr_ip_to_string(&buf, net), prefix_len);
}

void
process_import_nlh(const struct nlmsghdr *nlh, bool is_delete)
{
  union olsr_ip_addr prefix;
  uint8_t prefix_len;

  if (olsr_cnf->import_proto == 0) {
    return;
  }

  if (convert_route(nlh, &prefix, &prefix_len)) {
    return;
  }

  if (is_delete) {
    import_hna_remove(&olsr_cnf->hna_entries, &prefix, prefix_len);
  } else {
    import_hna_add(&olsr_cnf->hna_entries, &prefix, prefix_len);
  }
}

static int
dump_request(int sock)
{
  struct {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
  } req;

  memset(&req, 0, sizeof(req));

  req.nlh.nlmsg_type = RTM_GETROUTE;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_seq = time(NULL);
  req.rtm.rtm_family = olsr_cnf->ip_version;

  return send(sock, &req, sizeof(req), 0);
}

static int
recv_reply(int sock, char **answer)
{
  struct sockaddr_nl nladdr;
  struct iovec iov = { .iov_base = NULL, .iov_len = 0 };
  struct msghdr msg = {
    .msg_name = &nladdr,
    .msg_namelen = sizeof(nladdr),
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };
  char *buf;
  int len;

  do {
    len = recvmsg(sock, &msg, MSG_PEEK | MSG_TRUNC);
  } while (len < 0 && errno == EINTR);

  if (len <= 0) {
    return len < 0 ? -errno : -ENODATA;
  }

  buf = olsr_malloc(len, "route import netlink buffer");
  iov.iov_base = buf;
  iov.iov_len = len;

  do {
    len = recvmsg(sock, &msg, 0);
  } while (len < 0 && errno == EINTR);

  if (len <= 0) {
    free(buf);
    return len < 0 ? -errno : -ENODATA;
  }

  *answer = buf;

  return len;
}

/*
 * A full table dump spans as many datagrams as it needs, so read until
 * NLMSG_DONE - stopping at the first one silently imports a fraction of
 * the table on a router with many routes.
 */
static int
dump_response(int sock, struct ip_prefix_list **out)
{
  bool done = false;

  while (!done) {
    char *buf = NULL;
    struct nlmsghdr *nlh;
    int msglen = recv_reply(sock, &buf);

    if (msglen < 0) {
      return msglen;
    }

    for (nlh = (struct nlmsghdr *) buf; NLMSG_OK(nlh, (unsigned int) msglen); nlh = NLMSG_NEXT(nlh, msglen)) {
      union olsr_ip_addr prefix;
      uint8_t prefix_len;
      int status;

      if (nlh->nlmsg_flags & NLM_F_DUMP_INTR) {
        free(buf);
        return -EAGAIN;
      }

      if (nlh->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }

      if (nlh->nlmsg_type == NLMSG_ERROR) {
        free(buf);
        return -EIO;
      }

      status = convert_route(nlh, &prefix, &prefix_len);

      if (status < 0) {
        free(buf);
        return -EINVAL;
      }

      if (status == 0) {
        import_hna_add(out, &prefix, prefix_len);
      }
    }

    free(buf);
  }

  return 0;
}

/*
 * Seeds the HNA list with what is already in the table. Uses its own
 * blocking socket rather than olsr_cnf->rtnl_s, which is non-blocking and
 * carries olsrd's own route operations.
 */
void
route_import_init(void)
{
  int sock;

  if (olsr_cnf->import_proto == 0) {
    return;
  }

  sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

  if (sock < 0) {
    OLSR_PRINTF(1, "route import: netlink socket: %s\n", strerror(errno));
    return;
  }

  if (dump_request(sock) < 0) {
    OLSR_PRINTF(1, "route import: route dump request: %s\n", strerror(errno));
  } else {
    int status = dump_response(sock, &olsr_cnf->hna_entries);

    if (status < 0) {
      /* not fatal: the route monitor still picks up everything that
       * changes from here on */
      OLSR_PRINTF(1, "route import: route dump failed: %s\n", strerror(-status));
    }
  }

  close(sock);
}
