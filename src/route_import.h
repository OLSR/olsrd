/*
 * Import kernel routes installed by another routing daemon as OLSR HNAs.
 */

#ifndef OLSRD_ROUTE_IMPORT_H
#define OLSRD_ROUTE_IMPORT_H

#include <stdbool.h>
#include <linux/netlink.h>

void process_import_nlh(const struct nlmsghdr *nlh, bool is_delete);
void route_import_init(void);

#endif /* OLSRD_ROUTE_IMPORT_H */
