/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2009, the olsr.org team - see HISTORY file
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>

/* System includes */
#include <stddef.h>             /* NULL */
#include <sys/types.h>          /* ssize_t */
#include <string.h>             /* strerror() */
#include <stdarg.h>             /* va_list, va_start, va_end */
#include <errno.h>              /* errno */
#include <assert.h>             /* assert() */
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_ether.h>     /* ETH_P_IP */
#include <linux/if_packet.h>    /* struct sockaddr_ll, PACKET_MULTICAST */
#include <signal.h>             /* sigset_t, sigfillset(), sigdelset(), SIGINT */
#include <netinet/ip.h>         /* struct ip */
#include <netinet/udp.h>        /* struct udphdr */
#include <unistd.h>             /* close() */

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <time.h>

/* OLSRD includes */
#include "plugin_util.h"        /* set_plugin_int */
#include "defs.h"               /* olsr_cnf, //OLSR_PRINTF */
#include "ipcalc.h"
#include "olsr.h"               /* //OLSR_PRINTF */
#include "mid_set.h"            /* mid_lookup_main_addr() */
#include "link_set.h"           /* get_best_link_to_neighbor() */
#include "net_olsr.h"           /* ipequal */
#include "parser.h"

#include "olsrd_drophna.h"


char * get_ipv4_str(uint32_t address, char *s, size_t maxlen);
char * get_ipv6_str(unsigned char* address, char *s, size_t maxlen);

/* -------------------------------------------------------------------------
 * Function   : olsr_blacklist_parser
 * Description: Function to be passed to the parser engine. This function
 *              processes the incoming message and passes it on if necessary.
 * Input      : m      - message to parse
 *              in_if  - interface to use (unused in this application)
 *              ipaddr - IP-address to use (unused in this application)
 * Output     : none
 * Return     : false if message should be supressed, true otherwise
 * Data Used  : none
 * ------------------------------------------------------------------------- */
bool
olsrd_drophna_parser(
    union olsr_message *m,
    struct interface *in_if __attribute__ ((unused)),
    union olsr_ip_addr *ipaddr __attribute__ ((unused))
){

  uint8_t olsr_msgtype;
  olsr_reltime vtime;
  uint16_t olsr_msgsize;
  union olsr_ip_addr originator;
  uint8_t hop_count;
  uint16_t msg_seq_number;

  int hnasize;
  const uint8_t *curr, *curr_end;

  struct ipaddr_str buf;
#ifdef DEBUG
  OLSR_PRINTF(5, "Processing HNA\n");
#endif

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

  hnasize = olsr_msgsize - 8 - olsr_cnf->ipsize;
  curr_end = (const uint8_t *)m + olsr_msgsize;

  /* validate originator */
  pkt_get_ipaddress(&curr, &originator);
  /*printf("HNA from %s\n\n", olsr_ip_to_string(&buf, &originator)); */

  /* ttl */
  pkt_ignore_u8(&curr);

  /* hopcnt */
  pkt_get_u8(&curr, &hop_count);

  /* seqno */
  pkt_get_u16(&curr, &msg_seq_number);

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
            uint8_t *dest = curr - 2 * olsr_cnf->ipsize;
            memmove(dest, curr, curr_end - curr);
            curr_end -= 2 * olsr_cnf->ipsize;
            curr = dest;
            if (olsr_cnf->ip_version == AF_INET) {
                m->v4.olsr_msgsize -= 2 * olsr_cnf->ipsize;
            }
            else {
                m->v6.olsr_msgsize -= 2 * olsr_cnf->ipsize;
            }
            continue;
        }
        return false;
    }
  }
	return true;
}

/* -------------------------------------------------------------------------
 * Function   : get_ipv4_str
 * Description: Convert the specified address to an IPv4 compatible string
 * Input      : address - IPv4 address to convert to string
 *              s       - string buffer to contain the resulting string
 *              maxlen  - maximum length of the string buffer
 * Output     : none
 * Return     : Pointer to the string buffer containing the result
 * Data Used  : none
 * ------------------------------------------------------------------------- */
char *
get_ipv4_str(uint32_t address, char *s, size_t maxlen)
{
  struct sockaddr_in v4;

  v4.sin_addr.s_addr = address;
  inet_ntop(AF_INET, &v4.sin_addr, s, maxlen);

  return s;
}

/* -------------------------------------------------------------------------
 * Function   : get_ipv6_str
 * Description: Convert the specified address to an IPv4 compatible string
 * Input      : address - IPv6 address to convert to string
 *              s       - string buffer to contain the resulting string
 *              maxlen  - maximum length of the string buffer
 * Output     : none
 * Return     : Pointer to the string buffer containing the result
 * Data Used  : none
 * ------------------------------------------------------------------------- */
char *
get_ipv6_str(unsigned char* address, char *s, size_t maxlen)
{
  struct sockaddr_in6 v6;

  memcpy(v6.sin6_addr.s6_addr, address, sizeof(v6.sin6_addr.s6_addr));
  inet_ntop(AF_INET6, &v6.sin6_addr, s, maxlen);

  return s;
}

void olsrd_drophna_init() {
}
