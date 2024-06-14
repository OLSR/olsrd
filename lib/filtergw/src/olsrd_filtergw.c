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

#include <arpa/inet.h>

#include "defs.h"
#include "ipcalc.h"
#include "log.h"
#include "olsr.h"
#include "olsr_cfg.h"
#include "olsr_types.h"
#include "olsrd_filtergw.h"
#include "parser.h"
#include "routing_table.h"
#include "scheduler.h"

#include <errno.h>
#include <net/route.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int is_allowlist = 0;

static struct filter_list *add_to_filter_list(const char *,
                                              struct filter_list *);

struct originator_list {
  union olsr_ip_addr originator;
  struct originator_list *next;
};

struct filter_group {
  struct originator_list *originator_list;
  struct filter_group *next;
};

struct int_name_list {
  char *int_name;
  struct int_name_list *next;
};

struct filter_int_name_group {
  struct int_name_list *int_name_list;
  struct hna_group *next;
};

static struct filter_group *filter_groups = NULL;
static struct filter_int_name_group *filter_int_name_groups = NULL;

// Delcaring function prototype here, fixes build error with clang-16
// Refer: https://bugs.gentoo.org/898090
int should_filter(union olsr_ip_addr *originator);

int check_interface(struct interface_olsr *in_if);

/* -------------------------------------------------------------------------
 * Function   : add_to_originator_list
 * Description: Add a new ip to originator list
 * Input      : originator_address - the address of originator
 *              the_originator_list - the list of originators
 * Output     : none
 * Return     : a pointer to the newly added originator, i.e. start of the list
 * Data Used  : none
 * ------------------------------------------------------------------------- */
/* add the valid IPs to the head of the list */
static struct originator_list *
add_to_originator_list(union olsr_ip_addr *originator_address,
                       struct originator_list *the_originator_list) {
  struct originator_list *new = calloc(1, sizeof(struct originator_list));
  if (!new) {
    olsr_exit("FILTERGW: Out of memory", EXIT_FAILURE);
  }
  memcpy(&new->originator, originator_address, olsr_cnf->ipsize);
  new->next = the_originator_list;
  return new;
}

static struct int_name_list *
add_to_int_name_list(const char *int_name,
                     struct int_name_list *the_int_name_list) {
  struct int_name_list *new = calloc(1, sizeof(struct int_name_list));
  if (!new) {
    olsr_exit("FILTERGW: Out of memory", EXIT_FAILURE);
  }
  new->int_name = strdup(int_name);
  new->next = the_int_name_list;
  return new;
}

/**
 * read config file parameters
 */
static int set_plugin_filter(const char *value,
                             void *data __attribute__((unused)),
                             set_plugin_parameter_addon addon
                             __attribute__((unused))) {
  union olsr_ip_addr addr;

  if (inet_pton(olsr_cnf->ip_version, value, &addr) <= 0) {
    OLSR_PRINTF(0, "Illegal IP address \"%s\"", value);
    return 1;
  }

  if (filter_groups == NULL) {
    struct filter_group *new = calloc(1, sizeof(struct filter_group));
    if (new == NULL) {
      olsr_exit("FILTERGW: Out of memory", EXIT_FAILURE);
    }
    filter_groups = new;
    new->next = filter_groups;
  }

  filter_groups->originator_list =
      add_to_originator_list(&addr, filter_groups->originator_list);

  return 0;
}

static int parse_int_filter(const char *value,
                            void *data __attribute__((unused)),
                            set_plugin_parameter_addon addon
                            __attribute__((unused))) {
  if (filter_int_name_groups == NULL) {
    struct filter_group *new = calloc(1, sizeof(struct filter_int_name_group));
    if (new == NULL) {
      olsr_exit("FILTERGW: Out of memory", EXIT_FAILURE);
    }
    filter_groups = new;
    new->next = filter_groups;
  }

  filter_int_name_groups->int_name_list =
      add_to_int_name_list(value, filter_int_name_groups->int_name_list);

  return 0;
}

/* -------------------------------------------------------------------------
 * Function   : olsrd_filtergw_parser
 * Description: Function to be passed to the parser engine. This function
 *              processes the incoming message and filters gw hna's.
 * Input      : m      - message to parse
 *              in_if  - interface to use (unused in this application)
 *              ipaddr - IP-address to use (unused in this application)
 * Output     : none
 * Return     : false if message should be supressed, true otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
bool olsrd_filtergw_parser(union olsr_message *m,
                           struct interface_olsr *in_if __attribute__((unused)),
                           union olsr_ip_addr *ipaddr __attribute__((unused))) {

  uint8_t olsr_msgtype;
  olsr_reltime vtime;
  uint16_t olsr_msgsize;
  union olsr_ip_addr originator;

  int hnasize;
  const uint8_t *curr, *curr_end;
  uint8_t *olsr_msgsize_p, *curr_hna, *temp_msgsize;

  struct ipaddr_str buf;
#ifdef DEBUG
  OLSR_PRINTF(5, "Processing HNA\n");
#endif
  if (!check_interface(in_if))
    return true;

  /* Check if everyting is ok */
  if (!m) {
    return false;
  }
  curr = (const uint8_t *)m;

  /* olsr_msgtype */
  pkt_get_u8(&curr, &olsr_msgtype);
  if (olsr_msgtype != HNA_MESSAGE) {
    OLSR_PRINTF(1, "not a HNA message!\n");
    return false;
  }
  /* Get vtime */
  pkt_get_reltime(&curr, &vtime);

  /* olsr_msgsize */
  pkt_get_u16(&curr, &olsr_msgsize);

  /* validate originator */
  pkt_get_ipaddress(&curr, &originator);
  /*printf("HNA from %s\n\n", olsr_ip_to_string(&buf, &originator)); */

  if (!should_filter(&originator)) {
    return true;
  }

  /* ttl */
  pkt_ignore_u8(&curr);

  /* hopcnt */
  pkt_ignore_u8(&curr);

  /* seqno */
  pkt_ignore_u16(&curr);

  /* msgtype(1) + vtime(1) + msgsize(2) + ttl(1) + hopcnt(1) + seqno(2) = 8 */
  olsr_msgsize_p = (uint8_t *)m + 2;
  curr_hna = (uint8_t *)m + 8 + olsr_cnf->ipsize;
  curr_end = (const uint8_t *)m + olsr_msgsize;
  hnasize = olsr_msgsize - 8 - olsr_cnf->ipsize;

  if ((hnasize % (2 * olsr_cnf->ipsize)) != 0) {
    OLSR_PRINTF(1, "Illegal HNA message from %s with size %d!\n",
                olsr_ip_to_string(&buf, &originator), olsr_msgsize);
    return false;
  }

  while (curr < curr_end) {
    struct olsr_ip_prefix prefix;
    union olsr_ip_addr mask;

    pkt_get_ipaddress(&curr, &prefix.prefix);
    pkt_get_ipaddress(&curr, &mask);
    prefix.prefix_len = olsr_netmask_to_prefix(&mask);

    if (is_prefix_inetgw(&prefix)) {
      hnasize -= 2 * olsr_cnf->ipsize;
      if (0 < hnasize) {
        /* move the rest of the message forward over the gw HNA */
        memmove(curr_hna, curr, curr_end - curr);
        curr_end -= 2 * olsr_cnf->ipsize;
        curr = curr_hna;

        /* update the message size */
        temp_msgsize = olsr_msgsize_p;
        olsr_msgsize -= 2 * olsr_cnf->ipsize;
        pkt_put_u16(&temp_msgsize, olsr_msgsize);
        continue;
      }
      return false;
    } else {
      curr_hna += 2 * olsr_cnf->ipsize;
    }
  }
  return true;
}

static const struct olsrd_plugin_parameters plugin_parameters[] = {
    {.name = "originator",
     .set_plugin_parameter = &set_plugin_filter,
     .data = NULL},
    {.name = "interface",
     .set_plugin_parameter = &parse_int_filter,
     .data = NULL},
    {.name = "allowlist",
     .set_plugin_parameter = &set_plugin_int,
     .data = &is_allowlist},
};

void olsrd_get_plugin_parameters(const struct olsrd_plugin_parameters **params,
                                 int *size) {
  *params = plugin_parameters;
  *size = sizeof(plugin_parameters) / sizeof(*plugin_parameters);
}

int olsrd_plugin_init(void) {
  olsr_parser_add_function(&olsrd_filtergw_parser, HNA_MESSAGE);
  return 1;
}

void olsrd_plugin_fini(void) {
  while (filter_groups) {

    while (filter_groups->originator_list) {
      struct originator_list *next = filter_groups->originator_list->next;
      // free(&filter_groups->originator_list->originator);
      free(filter_groups->originator_list);
      filter_groups->originator_list = next;
    }

    struct filter_group *next = filter_groups->next;
    free(filter_groups);
  }
}

/* -------------------------------------------------------------------------
 * Function   : should_filter
 * Description: Function used by the parse engine to see if filter applies
 *              to given originator address.
 * Input      : originator - ip addr of originator that should be checked
 * Output     : none
 * Return     : false if gw should note be supressed, true otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
int should_filter(union olsr_ip_addr *originator) {
  int found = 0;

  if (filter_groups == NULL) {
    /* if it is allow list but no entry, filter every GW announcement */
    return is_allowlist;
  }

  /* for now we only have 1 list entry */
  struct originator_list *list = filter_groups->originator_list;
  for (list = filter_groups->originator_list; list; list = list->next) {
    if (ipequal(&list->originator, originator)) {
      found = 1;
      break;
    }
  }
  return is_allowlist ? !found : found;
}

int check_interface(struct interface_olsr *in_if) {
  if (filter_int_name_groups == NULL) {
    /* if no interface is given, apply on all interfaces */
    return 1;
  }

  struct int_name_list *list = filter_int_name_groups->int_name_list;
  for (list = filter_int_name_groups->int_name_list; list; list = list->next) {
    if (strcmp(list->int_name, in_if->int_name) == 0)
      return 1;
  }
  return 0;
}
