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

#include "olsrd_conf.h"
#include "builddata.h"
#include "ipcalc.h"
#include "net_olsr.h"
#include "common/autobuf.h"
#include "egressTypes.h"
#include "lock_file.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <linux/rtnetlink.h>
#else
#define RTPROT_BOOT 3
#endif

int olsrd_write_cnf(struct olsrd_config *cnf, const char *fname) {
  FILE *fd;
  struct autobuf abuf;

  fd = fopen(fname, "w");

  if (fd == NULL) {
    fprintf(stderr, "Could not open file %s for writing\n%s\n", fname, strerror(errno));
    return -1;
  }

  printf("Writing config to file \"%s\".... ", fname);
  abuf_init(&abuf, AUTOBUFCHUNK);
  olsrd_write_cnf_autobuf(&abuf, cnf);
  if (fwrite(abuf.buf, abuf.len, 1, fd) < (size_t)abuf.len) {
    fprintf(stderr, "Error, could not write the complete config file.\n");
  }
  abuf_free(&abuf);
  fclose(fd);

  printf("DONE\n");

  return 1;
}

static int
if_appendf(struct autobuf *autobuf, bool comments, const char *fmt, ...)  __attribute__ ((format(printf, 3, 4)));

static int
if_appendf(struct autobuf *autobuf, bool comments, const char *fmt, ...)
{
  int rv;
  va_list ap;
  char *first;

  if (!comments) {
    va_start(ap, fmt);
    first = va_arg(ap, char*);
    va_end(ap);
    if (*first) {
      return 0;
    }
  }

  va_start(ap, fmt);
  rv = abuf_vappendf(autobuf, fmt, ap);
  va_end(ap);
  return rv;
}

static void olsrd_write_hna_autobuf(int ip_version, struct ip_prefix_list *hna, struct autobuf *out, struct olsrd_config *cnf) {
  struct ip_prefix_list *hna1 = (cnf->ip_version == ip_version) ? hna : NULL;

  abuf_appendf(out, "Hna%u\n"
    "{\n",
    ip_version == AF_INET ? 4 : 6);

  if (!hna1) {
    if (ip_version == AF_INET)
      abuf_puts(out,
          "# Internet gateway\n"
          "# 0.0.0.0   0.0.0.0\n"
          "# specific small networks reachable through this node\n"
          "# 15.15.0.0 255.255.255.0\n");
    else
      abuf_puts(out,
          "# Internet gateway\n"
          "#   0::                     0\n"
          "# specific small networks reachable through this node\n"
          "#   fec0:2200:106:0:0:0:0:0 48\n");
  } else
    while (hna1) {
      struct ipaddr_str strbuf;
      abuf_appendf(out, "    %s\n", olsr_ip_prefix_to_string(&hna1->net));
      hna1 = hna1->next;
    }
  abuf_appendf(out, "}\n");
}

static void olsrd_write_if_autobuf(struct autobuf *out, struct olsrd_config *cnf, struct if_config_options *cnfi, bool comments) {
  struct ipaddr_str ipbuf;
  struct olsr_lq_mult *mult;

  abuf_puts(out, "{\n");
  if (comments) abuf_appendf(out,
    "    # Interface Mode is used to prevent unnecessary\n"
    "    # packet forwarding on switched ethernet interfaces\n"
    "    # valid Modes are \"mesh\" and \"ether\"\n"
    "    # (default is \"%s\")\n"
    "\n", OLSR_IF_MODE[DEF_IF_MODE]);
  if_appendf(out, comments, "    %sMode \"%s\"\n",
      cnfi->mode == DEF_IF_MODE ? "# " : "",
      OLSR_IF_MODE[cnfi->mode]);
  if (comments) abuf_puts(out,
    "\n"
    "    # IPv4 broadcast address for outgoing OLSR packets.\n"
    "    # One useful example would be 255.255.255.255\n"
    "    # The second useful value would be to\n"
    "    # specify the peer address of an ptp-tunnel.\n"
    "    # another name of this parameter is \"IPv4Multicast\"\n"
    "    # (default is 0.0.0.0, which triggers the usage of the\n"
    "    # interface broadcast IP)\n"
    "\n");
  if_appendf(out, comments, "    %sIp4Broadcast      %s\n",
      cnfi->ipv4_multicast.v4.s_addr == 0 ? "# " : "",
      inet_ntop(AF_INET, &cnfi->ipv4_multicast, ipbuf.buf, sizeof(ipbuf)));
  if (comments) abuf_appendf(out,
    "\n"
    "    # IPv6 multicast address\n"
    "    # (default is %s, the manet-router linklocal multicast)\n"
    "\n", inet_ntop(AF_INET6, &ipv6_def_multicast, ipbuf.buf, sizeof(ipbuf)));
  if_appendf(out, comments, "    %sIPv6Multicast %s\n",
      memcmp(&cnfi->ipv6_multicast, &ipv6_def_multicast, sizeof(ipv6_def_multicast)) == 0 ? "# " : "",
      inet_ntop(AF_INET6, &cnfi->ipv6_multicast, ipbuf.buf, sizeof(ipbuf)));
  if (comments) abuf_puts(out,
    "\n"
    "    # IPv4 src address for outgoing OLSR packages\n"
    "    # (default is 0.0.0.0, which triggers usage of the interface IP)\n"
    "\n");
  if_appendf(out, comments, "    %sIPv4Src %s\n",
      cnfi->ipv4_src.v4.s_addr == 0 ? "# " : "",
      inet_ntop(AF_INET, &cnfi->ipv4_src, ipbuf.buf, sizeof(ipbuf)));
  if (comments) abuf_puts(out,
    "\n"
    "    # IPv6 src prefix. OLSRd will choose one of the interface IPs\n"
    "    # which matches the prefix of this parameter.\n"
    "    # (default is 0::/0, which triggers the usage\n"
    "    # of a not-linklocal interface IP)\n"
    "\n");
  {
    int saved = cnf->ip_version;
    cnf->ip_version = AF_INET6;
    if_appendf(out, comments, "    %sIPv6Src %s\n",
      cnfi->ipv6_src.prefix_len == 0 ? "# " : "",
          olsr_ip_prefix_to_string(&cnfi->ipv6_src));
    cnf->ip_version = saved;
  }
  if (comments) abuf_appendf(out,
    "\n"
    "    # Emission intervals in seconds.\n"
    "    # If not defined, Freifunk network defaults are used.\n"
    "    # (defaults: Hello = %.1f/%.1f,  TC  = %.1f/%.1f,\n"
    "    #            MID   = %.1f/%.1f, HNA = %.1f/%.1f)\n"
    "\n",
    (double)HELLO_INTERVAL, (double)NEIGHB_HOLD_TIME,
    (double)TC_INTERVAL,    (double)TOP_HOLD_TIME,
    (double)MID_INTERVAL,   (double)MID_HOLD_TIME,
    (double)HNA_INTERVAL,   (double)HNA_HOLD_TIME
    );
  if_appendf(out, comments, "    %sHelloInterval       %3.1f\n",
      cnfi->hello_params.emission_interval == HELLO_INTERVAL ? "# " : "",
      (double)cnfi->hello_params.emission_interval);
  if_appendf(out, comments, "    %sHelloValidityTime   %3.1f\n",
      cnfi->hello_params.validity_time == NEIGHB_HOLD_TIME ? "# " : "",
      (double)cnfi->hello_params.validity_time);
  if_appendf(out, comments, "    %sTcInterval          %3.1f\n",
      cnfi->tc_params.emission_interval == TC_INTERVAL ? "# " : "",
      (double)cnfi->tc_params.emission_interval);
  if_appendf(out, comments, "    %sTcValidityTime      %3.1f\n",
      cnfi->tc_params.validity_time == TOP_HOLD_TIME ? "# " : "",
      (double)cnfi->tc_params.validity_time);
  if_appendf(out, comments, "    %sMidInterval         %3.1f\n",
      cnfi->mid_params.emission_interval == MID_INTERVAL ? "# " : "",
      (double)cnfi->mid_params.emission_interval);
  if_appendf(out, comments, "    %sMidValidityTime     %3.1f\n",
      cnfi->mid_params.validity_time == MID_HOLD_TIME ? "# " : "",
      (double)cnfi->mid_params.validity_time);
  if_appendf(out, comments, "    %sHnaInterval         %3.1f\n",
      cnfi->hna_params.emission_interval == HNA_INTERVAL ? "# " : "",
      (double)cnfi->hna_params.emission_interval);
  if_appendf(out, comments, "    %sHnaValidityTime     %3.1f\n",
      cnfi->hna_params.validity_time == HNA_HOLD_TIME ? "# " : "",
      (double)cnfi->hna_params.validity_time);
  if (comments) abuf_puts(out,
    "\n"
    "    # When multiple links exist between hosts\n"
    "    # the weight of interface is used to determine\n"
    "    # the link to use. Normally the weight is\n"
    "    # automatically calculated by olsrd based\n"
    "    # on the characteristics of the interface,\n"
    "    # but here you can specify a fixed value.\n"
    "    # Olsrd will choose links with the lowest value.\n"
    "    # Note:\n"
    "    # Interface weight is used only when LinkQualityLevel is set to 0.\n"
    "    # For any other value of LinkQualityLevel, the interface ETX\n"
    "    # value is used instead.\n");
  if_appendf(out, comments, "    %sWeight %d\n",
      !cnfi->weight.fixed ? "# " : "",
      cnfi->weight.value);
  if (comments) abuf_puts(out,
    "\n"
    "    # If a certain route should be preferred\n"
    "    # or ignored by the mesh, the Link Quality\n"
    "    # value of a node can be multiplied with a factor\n"
    "    # entered here. In the example the route\n"
    "    # using 192.168.0.1 would rather be ignored.\n"
    "    # A multiplier of 0.5 will result in a small\n"
    "    # (bad) LinkQuality value and a high (bad)\n"
    "    # ETX value.\n"
    "    # Note:\n"
    "    # Link quality multiplier is used only when\n"
    "    # LinkQualityLevel is greater than 0.\n"
    "\n");
  mult = cnfi->lq_mult;

  if (mult == NULL) {
    if (comments) {
      abuf_puts(out, "    # example 1: reduce LQ to 192.168.0.1 by half\n");
      abuf_puts(out, "    # LinkQualityMult 192.168.0.1 0.5\n");
      abuf_puts(out, "\n");
      abuf_puts(out, "    # example 2: reduce LQ to all nodes on this interface by 20%\n");
      abuf_puts(out, "    # LinkQualityMult default 0.8\n");
    }
  } else {
    while (mult != NULL) {
      if_appendf(out, comments, "    LinkQualityMult    %s %0.2f\n",
          olsr_ip_to_string(&ipbuf, &mult->addr),
          (double)((float)(mult->value) / 65536.0f));
      mult = mult->next;
    }
  }
  abuf_puts(out, "}\n");
}

static struct autobuf config_cache;

void olsrd_cfgfile_init(void) {
  abuf_init(&config_cache, AUTOBUFCHUNK);
}

void olsrd_cfgfile_cleanup(void) {
  abuf_free(&config_cache);
}

void olsrd_write_cnf_autobuf(struct autobuf *out, struct olsrd_config *cnf) {
  if (!config_cache.len) {
    olsrd_write_cnf_autobuf_uncached(&config_cache, cnf);
  }

  abuf_concat(out, &config_cache);
}

void olsrd_write_cnf_autobuf_uncached(struct autobuf *out, struct olsrd_config *cnf) {
  struct ip_prefix_list *hna = cnf->hna_entries;
  struct olsr_if *interf = cnf->interfaces;
  struct plugin_entry *plugins = cnf->plugins;
  struct plugin_param *pl_param;
  struct ip_prefix_list *ipc_nets = cnf->ipc_nets;

  struct ipaddr_str ipbuf;
  bool first;

  abuf_appendf(out, "#\n"
      "# Configuration file for %s\n"
      "# automatically generated by olsrd-cnf parser v. %s\n"
      "#\n"
      "\n",
      olsrd_version, PARSER_VERSION);
  abuf_appendf(out,
    "# OLSR.org routing daemon config file\n"
    "# This file contains ALL available options and explanations about them\n"
    "#\n"
    "# Lines starting with a # are discarded\n"
    "#\n"
    "\n"
    "#### ATTENTION for IPv6 users ####\n"
    "# Because of limitations in the parser IPv6 addresses must NOT\n"
    "# begin with a \":\", so please add a \"0\" as a prefix.\n"
    "\n"
    "###########################\n"
    "### Basic configuration ###\n"
    "###########################\n"
    "# keep this settings at the beginning of your first configuration file\n"
    "\n"
    "# Debug level (0-9)\n"
    "# If set to 0 the daemon runs in the background, unless \"NoFork\" is set to true\n"
    "# (default is %u)\n"
    "\n", DEF_DEBUGLVL);
  abuf_appendf(out, "%sDebugLevel  %d\n",
      cnf->debug_level == DEF_DEBUGLVL ? "# " : "",
      cnf->debug_level);
  abuf_appendf(out,
    "\n"
    "# IP version to use (4 or 6)\n"
    "# (default is %u)\n"
    "\n", (DEF_IP_VERSION == AF_INET) ? 4 : 6);
  abuf_appendf(out, "%sIpVersion %d\n",
      cnf->ip_version == DEF_IP_VERSION ? "# " : "",
      cnf->ip_version == AF_INET ? 4 : 6);
  abuf_appendf(out,
    "\n"
    "#################################\n"
    "### OLSRd agent configuration ###\n"
    "#################################\n"
    "# this parameters control the settings of the routing agent which are not\n"
    "# related to the OLSR protocol and it's extensions\n"
    "\n"
    "# Clear the screen each time the internal state changes\n"
    "# (default is %s)\n"
    "\n", DEF_CLEAR_SCREEN ? "yes" : "no");
  abuf_appendf(out, "%sClearScreen     %s\n",
      cnf->clear_screen == DEF_CLEAR_SCREEN ? "# " : "",
      cnf->clear_screen ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Should olsrd keep on running even if there are\n"
    "# no interfaces available? This is a good idea\n"
    "# for a PCMCIA/USB hotswap environment.\n"
    "# (default is %s)\n"
    "\n", DEF_ALLOW_NO_INTS ? "yes" : "no");
  abuf_appendf(out, "%sAllowNoInt  %s\n",
      cnf->allow_no_interfaces == DEF_ALLOW_NO_INTS ? "# " : "",
      cnf->allow_no_interfaces ? "yes" : "no");
  abuf_puts(out,
    "\n"
    "# LockFile\n"
    "# The lockfile is used to prevent multiple OLSR instances running at the same\n"
    "# time.\n"
    "# (Linux/BSD default is \"/var/run/olsrd-ipv(4/6).lock\")\n"
    "# (Win32     default is \"[configfile]-ipv(4/6).lock\")\n"
    "\n");
  {
    char * lockfile_default = olsrd_get_default_lockfile(cnf);
    abuf_appendf(out, "%sLockFile \"%s\"\n",
        !strcmp(cnf->lock_file, lockfile_default) ? "# " : "",
        cnf->lock_file);
    free(lockfile_default);
  }
  abuf_appendf(out,
    "\n"
    "# Polling rate for OLSR sockets in seconds (float).\n"
    "# (default is %.2f)\n"
    "\n", (double)DEF_POLLRATE);
  abuf_appendf(out, "%sPollrate  %.2f\n",
      cnf->pollrate == (float)DEF_POLLRATE ? "# " : "",
      (double)cnf->pollrate);
  abuf_appendf(out,
    "\n"
    "# Interval to poll network interfaces for configuration changes (in seconds).\n"
    "# Linux systems can detect interface statechange via netlink sockets.\n"
    "# (default is %.1f)\n"
    "\n", (double)DEF_NICCHGPOLLRT);
  abuf_appendf(out, "%sNicChgsPollInt  %.1f\n",
      cnf->nic_chgs_pollrate == (float)DEF_NICCHGPOLLRT ? "# " : "",
      (double)cnf->nic_chgs_pollrate);
  abuf_appendf(out,
    "\n"
    "# TOS(type of service) value for the IP header of control traffic.\n"
    "# (default is %u)\n"
    "\n", DEF_TOS);
  abuf_appendf(out, "%sTosValue %u\n",
      cnf->tos == DEF_TOS ? "# " : "",
      cnf->tos);
  abuf_appendf(out,
    "\n"
    "# FIBMetric controls the metric value of the host-routes OLSRd sets.\n"
    "# - \"flat\" means that the metric value is always 2 (or as configured\n"
    "#   with FIBMetricDefault). This is the preferred value because it helps\n"
    "#   the linux kernel routing to clean up older routes\n"
    "# - \"correct\" use the hopcount as the metric value.\n"
    "# - \"approx\" use the hopcount as the metric value too, but does only update the\n"
    "#   hopcount if the nexthop changes too\n"
    "# (default is \"%s\")\n"
    "\n", FIB_METRIC_TXT[DEF_FIB_METRIC]);
  abuf_appendf(out, "%sFIBMetric \"%s\"\n",
      cnf->fib_metric == DEF_FIB_METRIC ? "# " : "",
      FIB_METRIC_TXT[cnf->fib_metric]);
  abuf_appendf(out,
    "\n"
    "# Default FIB metric.\n"
    "# The kernel FIB does not need to know the metric of a route.\n"
    "# This saves us from enqueuing/dequeueing hopcount only changes.\n"
    "# (default is %u)\n"
    "\n", DEF_FIB_METRIC_DEFAULT);
  abuf_appendf(out, "%sFIBMetricDefault %u\n",
      cnf->fib_metric_default == DEF_FIB_METRIC_DEFAULT? "# " : "",
      cnf->fib_metric_default);
  abuf_appendf(out,
    "\n"
    "#######################################\n"
    "### Linux specific OLSRd extensions ###\n"
    "#######################################\n"
    "# these parameters are only working on linux at the moment, but might become\n"
    "# useful on BSD in the future\n"
    "\n"
    "# SrcIpRoutes tells OLSRd to set the Src flag of host routes to the originator-ip\n"
    "# of the node. In addition to this an additional localhost device is created\n"
    "# to make sure the returning traffic can be received.\n"
    "# (default is \"%s\")\n"
    "\n", DEF_USE_SRCIP_ROUTES ? "yes" : "no");
  abuf_appendf(out, "%sSrcIpRoutes %s\n",
      cnf->use_src_ip_routes == DEF_USE_SRCIP_ROUTES ? "# " : "",
      cnf->use_src_ip_routes ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Specify the proto tag to be used for routes olsr inserts into kernel\n"
    "# currently only implemented for linux\n"
    "# valid values under linux are 1 .. 254\n"
    "# 1 gets remapped by olsrd to 0 UNSPECIFIED (1 is reserved for ICMP redirects)\n"
    "# 2 KERNEL routes (not very wise to use)\n"
    "# 3 BOOT (should in fact not be used by routing daemons)\n"
    "# 4 STATIC\n"
    "# 8 .. 15 various routing daemons (gated, zebra, bird, & co)\n"
    "# (default is %u which gets replaced by an OS-specific default value;\n"
    "# %u (BOOT) under linux (for backward compatibility)\n"
    "\n", DEF_RTPROTO, RTPROT_BOOT);
  {
    int expected = DEF_RTPROTO;
#ifdef __linux__
    expected = RTPROT_BOOT;
#endif
    abuf_appendf(out, "%sRtProto %u\n",
        cnf->rt_proto == expected ? "# " : "",
        cnf->rt_proto == expected ? DEF_RTPROTO : cnf->rt_proto);
  }
  abuf_appendf(out,
    "\n"
    "# Route protocol whose host routes are announced as HNAs, so hosts\n"
    "# only another routing daemon knows about become reachable over olsr.\n"
    "# 0 disables the import. ImportPrefix, repeatable, bounds what may be\n"
    "# announced; without any, every host route of that protocol is taken\n"
    "\n");
  if (cnf->import_proto != DEF_IMPORTPROTO) {
    struct ip_prefix_list *hna;

    abuf_appendf(out, "ImportProto %u\n", cnf->import_proto);

    for (hna = cnf->import_prefixes; hna != NULL; hna = hna->next) {
      struct ipaddr_str addrbuf;
      abuf_appendf(out, "ImportPrefix %s/%d\n",
          olsr_ip_to_string(&addrbuf, &hna->net.prefix), hna->net.prefix_len);
    }
  } else {
    abuf_appendf(out, "# ImportProto %u\n", DEF_IMPORTPROTO);
  }

  abuf_appendf(out,
    "\n"
    "# Specifies the routing Table olsr uses\n"
    "# RtTable is for host routes, RtTableDefault for the route to the default\n"
    "# internet gateway (2 in case of IPv6+NIIT) and RtTableTunnel is for\n"
    "# routes to the ipip tunnels, valid values are 1 to 254\n"
    "# There is a special parameter \"auto\" (choose default below)\n"
    "# (with    smartgw: default is %u/%u/%u)\n"
    "# (without smartgw: default is %u/%u/%u, linux main table)\n"
    "\n",
    DEF_SGW_RT_TABLE_NR, DEF_SGW_RT_TABLE_DEFAULT_NR, DEF_SGW_RT_TABLE_TUNNEL_NR,
    DEF_RT_TABLE_NR, DEF_RT_TABLE_DEFAULT_NR, DEF_RT_TABLE_TUNNEL_NR);
  if (!cnf->smart_gw_active) {
    if (cnf->rt_table == DEF_RT_TABLE_NR)
      abuf_appendf(out, "%sRtTable        %s\n",
          "# ",
          "auto");
    else
      abuf_appendf(out, "%sRtTable        %u\n",
          "",
          cnf->rt_table);
    if (cnf->rt_table_default == DEF_RT_TABLE_DEFAULT_NR)
      abuf_appendf(out, "%sRtTableDefault %s\n",
          "# ",
          "auto");
    else
      abuf_appendf(out, "%sRtTableDefault %u\n",
          "",
          cnf->rt_table_default);
    if (cnf->rt_table_tunnel == DEF_RT_TABLE_TUNNEL_NR)
      abuf_appendf(out, "%sRtTableTunnel  %s\n",
          "# ",
          "auto");
    else
      abuf_appendf(out, "%sRtTableTunnel  %u\n",
          "",
          cnf->rt_table_tunnel);
  } else {
    if (cnf->rt_table == DEF_SGW_RT_TABLE_NR)
      abuf_appendf(out, "%sRtTable        %s\n",
          "# ",
          "auto");
    else
      abuf_appendf(out, "%sRtTable        %u\n",
          "",
          cnf->rt_table);
    if (cnf->rt_table_default == DEF_SGW_RT_TABLE_DEFAULT_NR)
      abuf_appendf(out, "%sRtTableDefault %s\n",
          "# ",
          "auto");
    else
      abuf_appendf(out, "%sRtTableDefault %u\n",
          "",
          cnf->rt_table_default);
    if (cnf->rt_table_tunnel == DEF_SGW_RT_TABLE_TUNNEL_NR)
      abuf_appendf(out, "%sRtTableTunnel  %s\n",
          "# ",
          "auto");
    else
      abuf_appendf(out, "%sRtTableTunnel  %u\n",
          "",
          cnf->rt_table_tunnel);
  }
  abuf_appendf(out,
    "\n"
    "# Specifies the policy rule priorities for the three routing tables and\n"
    "# a special rule for smartgateway routing (see README-Olsr-Extensions)\n"
    "# Priorities can only be set if three different routing tables are set.\n"
    "# if set the values must obey to condition\n"
    "# RtTablePriority less than RtTableDefaultOlsrPriority\n"
    "# less than RtTableTunnelPriority less than RtTableDefaultPriority\n"
    "# There are two special parameters, \"auto\" (choose fitting to SmartGW\n"
    "# mode) and \"none\" (do not set policy rule)\n");

  abuf_puts(out, "# (with    smartgw: default is ");
  if (cnf->rt_table_pri > 0)
    abuf_appendf(out,
      "%5d/",
      DEF_SGW_RT_TABLE_PRI);
  else
    abuf_appendf(out,
      "%5s/",
      "none");
  abuf_appendf(out,
    "%-5u/%-5u/%-5u)\n",
    DEF_SGW_RT_TABLE_PRI_BASE + DEF_SGW_RT_TABLE_DEFAULTOLSR_PRI_ADDER,
    DEF_SGW_RT_TABLE_PRI_BASE + DEF_SGW_RT_TABLE_DEFAULTOLSR_PRI_ADDER + DEF_SGW_RT_TABLE_TUNNEL_PRI_ADDER,
    DEF_SGW_RT_TABLE_PRI_BASE + DEF_SGW_RT_TABLE_DEFAULTOLSR_PRI_ADDER + DEF_SGW_RT_TABLE_TUNNEL_PRI_ADDER + DEF_SGW_RT_TABLE_DEFAULT_PRI_ADDER);

  abuf_puts(out, "# (without smartgw: default is ");
  if (cnf->rt_table_pri == DEF_RT_AUTO || cnf->rt_table_pri == DEF_RT_TABLE_PRI)
    abuf_appendf(out,
      "%5s/",
      "auto");
  else
    abuf_appendf(out,
      "%5d/",
      DEF_RT_TABLE_PRI);
  if (cnf->rt_table_defaultolsr_pri == DEF_RT_AUTO || cnf->rt_table_defaultolsr_pri == DEF_RT_TABLE_DEFAULTOLSR_PRI)
    abuf_appendf(out,
      "%-5s/",
      "auto");
  else
    abuf_appendf(out,
      "%-5d/",
      DEF_RT_TABLE_DEFAULTOLSR_PRI);
  if (cnf->rt_table_tunnel_pri == DEF_RT_AUTO || cnf->rt_table_tunnel_pri == DEF_RT_TABLE_TUNNEL_PRI)
    abuf_appendf(out,
      "%-5s/",
      "auto");
  else
    abuf_appendf(out,
      "%-5d/",
      DEF_RT_TABLE_TUNNEL_PRI);
  if (cnf->rt_table_default_pri == DEF_RT_AUTO || cnf->rt_table_default_pri == DEF_RT_TABLE_DEFAULT_PRI)
    abuf_appendf(out,
      "%-5s",
      "auto");
  else
    abuf_appendf(out,
      "%-5d",
      DEF_RT_TABLE_DEFAULT_PRI);
  abuf_puts(out, ")\n");

  abuf_puts(out, "\n");

  if (!cnf->smart_gw_active) {
    if (cnf->rt_table_pri == DEF_RT_AUTO || cnf->rt_table_pri == DEF_RT_TABLE_PRI)
      abuf_appendf(out, "# RtTablePriority            %s\n",
          "auto");
    else
      abuf_appendf(out, "RtTablePriority              %u\n",
          cnf->rt_table_pri);

    if (cnf->rt_table_defaultolsr_pri == DEF_RT_AUTO || cnf->rt_table_defaultolsr_pri == DEF_RT_TABLE_DEFAULTOLSR_PRI)
      abuf_appendf(out, "# RtTableDefaultOlsrPriority %s\n",
          "auto");
    else
      abuf_appendf(out, "RtTableDefaultOlsrPriority   %u\n",
          cnf->rt_table_defaultolsr_pri);

    if (cnf->rt_table_tunnel_pri == DEF_RT_AUTO || cnf->rt_table_tunnel_pri == DEF_RT_TABLE_TUNNEL_PRI)
      abuf_appendf(out, "# RtTableTunnelPriority      %s\n",
          "auto");
    else
      abuf_appendf(out, "RtTableTunnelPriority        %u\n",
          cnf->rt_table_tunnel_pri);

    if (cnf->rt_table_default_pri == DEF_RT_AUTO || cnf->rt_table_default_pri == DEF_RT_TABLE_DEFAULT_PRI)
      abuf_appendf(out, "# RtTableDefaultPriority     %s\n",
          "auto");
    else
      abuf_appendf(out, "RtTableDefaultPriority       %u\n",
          cnf->rt_table_default_pri);
  } else {
    if (cnf->rt_table_pri > 0)
      abuf_appendf(out, "RtTablePriority              %u\n",
          cnf->rt_table_pri);
    else
      abuf_appendf(out, "# RtTablePriority            %s\n",
          "none");

    abuf_appendf(out, "%sRtTableDefaultOlsrPriority %u\n",
        cnf->rt_table_defaultolsr_pri == (DEF_SGW_RT_TABLE_PRI_BASE + DEF_SGW_RT_TABLE_DEFAULTOLSR_PRI_ADDER) ? "# " : "",
        cnf->rt_table_defaultolsr_pri);

    abuf_appendf(out, "%sRtTableTunnelPriority      %u\n",
        cnf->rt_table_tunnel_pri == (DEF_SGW_RT_TABLE_PRI_BASE + DEF_SGW_RT_TABLE_DEFAULTOLSR_PRI_ADDER + DEF_SGW_RT_TABLE_TUNNEL_PRI_ADDER) ? "# " : "",
        cnf->rt_table_tunnel_pri);

    abuf_appendf(out, "%sRtTableDefaultPriority     %u\n",
        cnf->rt_table_default_pri == (DEF_SGW_RT_TABLE_PRI_BASE + DEF_SGW_RT_TABLE_DEFAULTOLSR_PRI_ADDER + DEF_SGW_RT_TABLE_TUNNEL_PRI_ADDER + DEF_SGW_RT_TABLE_DEFAULT_PRI_ADDER) ? "# " : "",
        cnf->rt_table_default_pri);
  }
  {
    bool expected = cnf->ip_version == AF_INET ? false : DEF_USE_NIIT;
    abuf_appendf(out,
      "\n"
      "# Activates (in IPv6 mode) the automatic use of NIIT\n"
      "# (see README-Olsr-Extensions)\n"
      "# (default is \"%s\" in IPv4 mode, \"%s\" in IPv6 mode)\n"
      "\n", expected ? "yes" : "no", DEF_USE_NIIT ? "yes" : "no");
    abuf_appendf(out, "%sUseNiit %s\n",
        cnf->use_niit == expected ? "# " : "",
        cnf->use_niit ? "yes" : "no");
  }
  abuf_appendf(out,
    "\n"
    "# Activates the smartgateway ipip tunnel feature.\n"
    "# See README-Olsr-Extensions for a description of smartgateways.\n"
    "# (default is \"%s\")\n"
    "\n", DEF_SMART_GW ? "yes" : "no");
  abuf_appendf(out, "%sSmartGateway %s\n",
      cnf->smart_gw_active == DEF_SMART_GW ? "# " : "",
      cnf->smart_gw_active ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Signals that the server tunnel must always be removed on shutdown,\n"
    "# irrespective of the interface up/down state during startup.\n"
    "# (default is \"%s\")\n"
    "\n", DEF_SMART_GW_ALWAYS_REMOVE_SERVER_TUNNEL ? "yes" : "no");
  abuf_appendf(out, "%sSmartGatewayAlwaysRemoveServerTunnel %s\n",
      cnf->smart_gw_always_remove_server_tunnel == DEF_SMART_GW_ALWAYS_REMOVE_SERVER_TUNNEL ? "# " : "",
      cnf->smart_gw_always_remove_server_tunnel ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Determines the maximum number of gateways that can be in use at any given\n"
    "# time. This setting is used to mitigate the effects of breaking connections\n"
    "# (due to the selection of a new gateway) on a dynamic network.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_USE_COUNT);
  abuf_appendf(out, "%sSmartGatewayUseCount %d\n",
      cnf->smart_gw_use_count == DEF_GW_USE_COUNT ? "# " : "",
      cnf->smart_gw_use_count);
  abuf_appendf(out,
    "\n"
    "# Determines the take-down percentage for a non-current smart gateway tunnel.\n"
    "# If the cost of the current smart gateway tunnel is less than this percentage\n"
    "# of the cost of the non-current smart gateway tunnel, then the non-current smart\n"
    "# gateway tunnel is taken down because it is then presumed to be 'too expensive'.\n"
    "# This setting is only relevant when SmartGatewayUseCount is larger than 1;\n"
    "# a value of 0 will result in the tunnels not being taken down proactively.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_TAKEDOWN_PERCENTAGE);
  abuf_appendf(out, "%sSmartGatewayTakeDownPercentage %d\n",
      cnf->smart_gw_takedown_percentage == DEF_GW_TAKEDOWN_PERCENTAGE ? "# " : "",
      cnf->smart_gw_takedown_percentage);
  abuf_puts(out,
    "\n"
    "# Determines the olsrd instance id, which is needed for proper cleanup\n"
    "# of multi-gateway iptables and ip rules when running multiple olsrd\n"
    "# instances on a node. This setting MUST be configured when the\n"
    "# multi-gateway mode is enabled and must be unique between the olsrd\n"
    "# instances running on the node. It may not contain whitespace and may\n"
    "# not be empty.\n"
    "# (default is <not set>)\n"
    "\n");
  abuf_appendf(out, "%sSmartGatewayInstanceId %s%s%s\n",
      !cnf->smart_gw_instance_id ? "# " : "",
      !cnf->smart_gw_instance_id ? "" : "\"",
      !cnf->smart_gw_instance_id ? "<not set>" : cnf->smart_gw_instance_id,
      !cnf->smart_gw_instance_id ? "" : "\"");
  abuf_puts(out,
    "\n"
    "# Determines the policy routing script that is executed during startup and\n"
    "# shutdown of olsrd. The script is only executed when SmartGatewayUseCount\n"
    "# is set to a value larger than 1. The script must setup policy routing\n"
    "# rules such that multi-gateway mode works. A sample script is included.\n"
    "# (default is <not set>)\n"
    "\n");
  abuf_appendf(out, "%sSmartGatewayPolicyRoutingScript %s%s%s\n",
      !cnf->smart_gw_policyrouting_script ? "# " : "",
      !cnf->smart_gw_policyrouting_script ? "" : "\"",
      !cnf->smart_gw_policyrouting_script ? "<not set>" : cnf->smart_gw_policyrouting_script,
      !cnf->smart_gw_policyrouting_script ? "" : "\"");
  abuf_puts(out,
    "\n"
    "# Determines the egress interfaces that are part of the multi-gateway setup and\n"
    "# therefore only relevant when SmartGatewayUseCount is larger than 1 (in which\n"
    "# case it must be explicitly set).\n"
    "# (default is not set)\n"
    "\n");
  abuf_appendf(out, "%sSmartGatewayEgressInterfaces",
      !cnf->smart_gw_egress_interfaces ? "# " : "");
  {
    struct sgw_egress_if * sgwegressif = olsr_cnf->smart_gw_egress_interfaces;
    if (!sgwegressif)
      abuf_puts(out, " \"\"");
    else
      while (sgwegressif) {
        abuf_appendf(out, " \"%s\"", sgwegressif->name);
        sgwegressif = sgwegressif->next;
      }
    abuf_puts(out, "\n");
  }
  abuf_appendf(out,
    "\n"
    "# SmartGatewayEgressFile declares the file that contains the bandwidth\n"
    "# parameters of the egress interfaces declared by SmartGatewayEgressInterfaces.\n"
    "# Every line in the file declares bandwidth parameters of an egress interface,\n"
    "# with the format:\n"
    "#   # this is a comment\n"
    "#   interface=upstream,downstream,pathcost,network/prefix,gateway\n"
    "# Only the upstream and downstream fields are mandatory, the other fields are\n"
    "# optional. An empty field signifies that its default should be used.\n"
    "# The field defaults are:\n"
    "#   upstream           = 0 (Kbps)\n"
    "#   downstream         = 0 (Kbps)\n"
    "#   pathcost           = 0 (dimensionless, 1024 is equivalent to 1 hop)\n"
    "#   network/prefix     = no default / not set\n"
    "#                        - network is an IP address\n"
    "#                        - prefix is a number in the range [0, 24] for IPv4\n"
    "#                          and in the range [0, 128] for IPv6\n"
    "#   gateway            = no default / not set (IP address)\n"
    "# (default is %s)\n"
    "\n", DEF_GW_EGRESS_FILE);
  {
    bool def = !cnf->smart_gw_egress_file || !strcmp(cnf->smart_gw_egress_file, DEF_GW_EGRESS_FILE);
    abuf_appendf(out, "%sSmartGatewayEgressFile \"%s\"\n",
      def ? "# " : "", def ? DEF_GW_EGRESS_FILE : cnf->smart_gw_egress_file);
  }
  abuf_appendf(out,
    "\n"
    "# Determines the period (in milliseconds) on which the SmartGatewayEgressFile\n"
    "# is checked for changes and processed if changed.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_EGRESS_FILE_PERIOD);
  abuf_appendf(out, "%sSmartGatewayEgressFilePeriod %u\n",
      cnf->smart_gw_egress_file_period == DEF_GW_EGRESS_FILE_PERIOD ? "# " : "",
      cnf->smart_gw_egress_file_period);
  abuf_appendf(out,
    "\n"
    "# Declares the file that is written by olsrd to contain the status of the smart\n"
    "# gateways and is only relevant when SmartGatewayUseCount is larger than 1.\n"
    "# (default is %s)\n"
      "\n", "<not set>");
    {
      bool def = !cnf->smart_gw_status_file || !strlen(cnf->smart_gw_status_file);
      abuf_appendf(out, "%sSmartGatewayStatusFile %s%s%s\n",
        def ? "# " : "",
        def ? "" : "\"",
        def ? "<not set>" : cnf->smart_gw_status_file,
        def ? "" : "\"");
    }
  abuf_appendf(out,
    "\n"
    "# Determines the routing tables offset for multi-gateway policy routing tables\n"
    "# See the policy routing script for an explanation.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_OFFSET_TABLES);
  abuf_appendf(out, "%sSmartGatewayTablesOffset %u\n",
      cnf->smart_gw_offset_tables == DEF_GW_OFFSET_TABLES ? "# " : "",
      cnf->smart_gw_offset_tables);
  abuf_appendf(out,
    "\n"
    "# Determines the policy routing rules offset for multi-gateway policy routing\n"
    "# rules. See the policy routing script for an explanation.\n"
    "# (default is %u, which indicates that the rules and tables should be aligned and\n"
    "# puts this value at SmartGatewayTablesOffset - # egress interfaces -\n"
    "# # olsr interfaces)\n"
    "\n", DEF_GW_OFFSET_RULES);
  abuf_appendf(out, "%sSmartGatewayRulesOffset %u\n",
      cnf->smart_gw_offset_rules == DEF_GW_OFFSET_RULES ? "# " : "",
      cnf->smart_gw_offset_rules);
  abuf_appendf(out,
    "\n"
    "# Allows the selection of a smartgateway with NAT (only for IPv4)\n"
    "# (default is \"%s\")\n"
    "\n", DEF_GW_ALLOW_NAT ? "yes" : "no");
  abuf_appendf(out, "%sSmartGatewayAllowNAT %s\n",
      cnf->smart_gw_allow_nat == DEF_GW_ALLOW_NAT ? "# " : "",
      cnf->smart_gw_allow_nat ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Determines the period (in milliseconds) on which a new smart gateway\n"
    "# selection is performed.\n"
    "# (default is %u milliseconds)\n"
    "\n", DEF_GW_PERIOD);
  abuf_appendf(out, "%sSmartGatewayPeriod %d\n",
      cnf->smart_gw_period == DEF_GW_PERIOD ? "# " : "",
      cnf->smart_gw_period);
  abuf_appendf(out,
    "\n"
    "# Determines the number of times the link state database must be stable\n"
    "# before a new smart gateway is selected.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_STABLE_COUNT);
  abuf_appendf(out, "%sSmartGatewayStableCount %d\n",
      cnf->smart_gw_stablecount == DEF_GW_STABLE_COUNT ? "# " : "",
      cnf->smart_gw_stablecount);
  abuf_appendf(out,
    "\n"
    "# When another gateway than the current one has a cost of less than the cost\n"
    "# of the current gateway multiplied by SmartGatewayThreshold then the smart\n"
    "# gateway is switched to the other gateway. The unit is percentage.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_THRESH);
  abuf_appendf(out, "%sSmartGatewayThreshold %d\n",
      cnf->smart_gw_thresh == DEF_GW_THRESH ? "# " : "",
      cnf->smart_gw_thresh);
  abuf_appendf(out,
    "\n"
    "# The weighing factor for the gateway uplink bandwidth (exit link, uplink).\n"
    "# See README-Olsr-Extensions for a description of smart gateways.\n"
    "# (default is %lu)\n"
    "\n", (long unsigned int)DEF_GW_WEIGHT_EXITLINK_UP);
  abuf_appendf(out, "%sSmartGatewayWeightExitLinkUp %d\n",
      cnf->smart_gw_weight_exitlink_up == DEF_GW_WEIGHT_EXITLINK_UP ? "# " : "",
      cnf->smart_gw_weight_exitlink_up);
  abuf_appendf(out,
    "\n"
    "# The weighing factor for the gateway downlink bandwidth (exit link, downlink).\n"
    "# See README-Olsr-Extensions for a description of smart gateways.\n"
    "# (default is %lu)\n"
    "\n", (long unsigned int)DEF_GW_WEIGHT_EXITLINK_DOWN);
  abuf_appendf(out, "%sSmartGatewayWeightExitLinkDown %d\n",
      cnf->smart_gw_weight_exitlink_down == DEF_GW_WEIGHT_EXITLINK_DOWN ? "# " : "",
      cnf->smart_gw_weight_exitlink_down);
  abuf_appendf(out,
    "\n"
    "# The weighing factor for the ETX costs.\n"
    "# See README-Olsr-Extensions for a description of smart gateways.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_WEIGHT_ETX);
  abuf_appendf(out, "%sSmartGatewayWeightEtx %d\n",
      cnf->smart_gw_weight_etx == DEF_GW_WEIGHT_ETX ? "# " : "",
      cnf->smart_gw_weight_etx);
  abuf_appendf(out,
    "\n"
    "# The divider for the ETX costs.\n"
    "# See README-Olsr-Extensions for a description of smart gateways.\n"
    "# (default is %u)\n"
    "\n", DEF_GW_DIVIDER_ETX);
  abuf_appendf(out, "%sSmartGatewayDividerEtx %d\n",
      cnf->smart_gw_divider_etx == DEF_GW_DIVIDER_ETX ? "# " : "",
      cnf->smart_gw_divider_etx);
  abuf_appendf(out,
      "\n"
      "# When a node advertises the maximum bandwidth and its ETX\n"
      "# is below the value of this setting then the resulting gateway\n"
      "# costs are equal to the ETX, otherwise the normal calculation\n"
      "# of the gateway costs applies.\n"
      "# (default is %u)\n"
      "\n", DEF_GW_MAX_COST_MAX_ETX);
  abuf_appendf(out, "%sSmartGatewayMaxCostMaxEtx %d\n",
        cnf->smart_gw_path_max_cost_etx_max == DEF_GW_MAX_COST_MAX_ETX ? "# " : "",
        cnf->smart_gw_path_max_cost_etx_max);
  abuf_appendf(out,
    "\n"
    "# Defines what kind of Uplink this node will publish as a\n"
    "# smartgateway. The existence of the uplink is detected by\n"
    "# a route to 0.0.0.0/0, ::ffff:0:0/96 and/or 2000::/3.\n"
    "# possible values are \"none\", \"ipv4\", \"ipv6\", \"both\"\n"
    "# (default is \"%s\")\n"
    "\n", GW_UPLINK_TXT[DEF_GW_TYPE]);
  abuf_appendf(out, "%sSmartGatewayUplink \"%s\"\n",
      cnf->smart_gw_type == DEF_GW_TYPE ? "# " : "",
      GW_UPLINK_TXT[cnf->smart_gw_type]);
  abuf_appendf(out,
    "\n"
    "# Specifies if the local ipv4 uplink use NAT\n"
    "# (default is \"%s\")\n"
    "\n", DEF_GW_UPLINK_NAT ? "yes" : "no");
  abuf_appendf(out, "%sSmartGatewayUplinkNAT %s\n",
      cnf->smart_gw_uplink_nat == DEF_GW_UPLINK_NAT ? "# " : "",
      cnf->smart_gw_uplink_nat ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Specifies the speed of the uplink in kilobit/s.\n"
    "# First parameter is upstream, second parameter is downstream\n"
    "# (default is %u/%u)\n"
    "\n", DEF_UPLINK_SPEED, DEF_DOWNLINK_SPEED);
  abuf_appendf(out, "%sSmartGatewaySpeed %d %d\n",
      cnf->smart_gw_uplink == DEF_UPLINK_SPEED && cnf->smart_gw_downlink == DEF_DOWNLINK_SPEED ? "# " : "",
      cnf->smart_gw_uplink, cnf->smart_gw_downlink);
  abuf_puts(out,
    "\n"
    "# Specifies the EXTERNAL ipv6 prefix of the uplink. A prefix\n"
    "# length of more than 64 is not allowed.\n"
    "# Only relevant when running in IPv6 mode.\n"
    "# (default is 0::/0)\n"
    "\n");
  {
    int saved = cnf->ip_version;
    cnf->ip_version = AF_INET6;
    abuf_appendf(out, "%sSmartGatewayPrefix %s\n",
        cnf->smart_gw_prefix.prefix_len == 0 ? "# " : "",
        olsr_ip_prefix_to_string(&cnf->smart_gw_prefix));
    cnf->ip_version = saved;
  }
  abuf_appendf(out,
    "\n"
    "##############################\n"
    "### OLSR protocol settings ###\n"
    "##############################\n"
    "\n"
    "# For testing purposes it may be nice to use another port for olsrd\n"
    "# for using another port than the IANA assigned one\n"
    "# for a production network, there should be a good reason!!\n"
    "# valid values are integers greater than 1, please be careful with\n"
    "# using reserved port numbers\n"
    "# (default is %u, the IANA assigned olsr-port)\n"
    "\n", DEF_OLSRPORT);
  abuf_appendf(out, "%sOlsrPort %u\n",
      cnf->olsrport == DEF_OLSRPORT ? "# " : "",
      cnf->olsrport);
  abuf_puts(out,
    "\n"
    "# Sets the main IP (originator ip) of the router. This IP will NEVER\n"
    "# change during the uptime of olsrd.\n"
    "# (default is 0.0.0.0, which triggers usage of the IP of the first interface)\n"
    "\n");
  {
    union olsr_ip_addr main_addr;
    memset(&main_addr, 0, sizeof(main_addr));

    abuf_appendf(out, "%sMainIp %s\n",
        !memcmp(&main_addr, &cnf->main_addr, (cnf->ip_version == AF_INET) ? sizeof(main_addr.v4) : sizeof(main_addr.v6)) ? "# " : "",
        olsr_ip_to_string(&ipbuf, &cnf->main_addr));
  }
  abuf_appendf(out,
    "\n"
    "# The fixed willingness to use (0-7)\n"
    "# If not set willingness will be calculated\n"
    "# dynamically based on battery/power status\n"
    "# (default is %u)\n"
    "\n", DEF_WILLINGNESS);
  abuf_appendf(out, "%sWillingness     %u\n",
      cnf->willingness == DEF_WILLINGNESS ? "# " : "",
      cnf->willingness);
  abuf_puts(out,
    "\n"
    "# HNA (Host network association) allows the OLSR to announce\n"
    "# additional IPs or IP subnets to the net that are reachable\n"
    "# through this node.\n"
    "# Syntax for HNA4 is \"network-address    network-mask\"\n"
    "# Syntax for HNA6 is \"network-address    prefix-length\"\n"
    "# (default is no HNA)\n");
  olsrd_write_hna_autobuf(AF_INET, hna, out, cnf);
  olsrd_write_hna_autobuf(AF_INET6, hna, out, cnf);
  abuf_appendf(out,
    "\n"
    "# Hysteresis for link sensing (only for hopcount metric)\n"
    "# Hysteresis adds more robustness to the link sensing\n"
    "# but delays neighbor registration.\n"
    "# (default is %s)\n"
    "\n", DEF_USE_HYST ? "yes" : "no");
  abuf_appendf(out, "%sUseHysteresis %s\n",
      cnf->use_hysteresis == DEF_USE_HYST ? "# " : "",
      cnf->use_hysteresis ? "yes" : "no");
  abuf_appendf(out,
    "\n"
    "# Hysteresis parameters (only for hopcount metric)\n"
    "# Do not alter these unless you know what you are doing!\n"
    "# Set to auto by default. Allowed values are floating point\n"
    "# values in the interval 0,1\n"
    "# THR_LOW must always be lower than THR_HIGH!!\n"
    "# (default is %.2f/%.2f/%.2f)\n"
    "\n", (double)HYST_SCALING, (double)HYST_THRESHOLD_HIGH, (double)HYST_THRESHOLD_LOW);
  abuf_appendf(out, "%sHystScaling  %.2f\n",
      cnf->hysteresis_param.scaling == (float)HYST_SCALING ? "# " : "",
      (double)cnf->hysteresis_param.scaling);
  abuf_appendf(out, "%sHystThrHigh  %.2f\n",
      cnf->hysteresis_param.thr_high == (float)HYST_THRESHOLD_HIGH ? "# " : "",
      (double)cnf->hysteresis_param.thr_high);
  abuf_appendf(out, "%sHystThrLow   %.2f\n",
      cnf->hysteresis_param.thr_low == (float)HYST_THRESHOLD_LOW ? "# " : "",
      (double)cnf->hysteresis_param.thr_low);
  abuf_appendf(out,
    "\n"
    "# TC redundancy\n"
    "# Specifies how much neighbor info should be sent in\n"
    "# TC messages. Because of a design problem in the 0.5.x\n"
    "# dijkstra implementation this value must be set to 2.\n"
    "# 2 - send all neighbors\n"
    "# (default is %u)\n"
    "\n", TC_REDUNDANCY);
  abuf_appendf(out, "%sTcRedundancy  %d\n",
      cnf->tc_redundancy == TC_REDUNDANCY ? "# " : "",
      cnf->tc_redundancy);
  abuf_appendf(out,
    "\n"
    "# MPR coverage specifies how many MPRs a node should\n"
    "# try select to reach every 2 hop neighbor. Because of\n"
    "# a design problem in the 0.5.x dijkstra algorithm this\n"
    "# value should be set to 7.\n"
    "# (default is %u)\n"
    "\n", MPR_COVERAGE);
  abuf_appendf(out, "%sMprCoverage %d\n",
      cnf->mpr_coverage == MPR_COVERAGE ? "# " : "",
      cnf->mpr_coverage);
  abuf_appendf(out,
    "\n"
    "################################\n"
    "### OLSR protocol extensions ###\n"
    "################################\n"
    "\n"
    "# Link quality level switch between hopcount and\n"
    "# cost-based (mostly ETX) routing. Because of\n"
    "# a design problem in the 0.5.x dijkstra algorithm this\n"
    "# value should not be set to 1.\n"
    "# 0 = do not use link quality\n"
    "# 2 = use link quality for MPR selection and routing\n"
    "# (default is %u)\n"
    "\n", DEF_LQ_LEVEL);
  abuf_appendf(out, "%sLinkQualityLevel %d\n",
      cnf->lq_level == DEF_LQ_LEVEL ? "# " : "",
      cnf->lq_level);
  abuf_appendf(out,
    "\n"
    "# Link quality algorithm (only for lq level 2)\n"
    "# (see README-Olsr-Extensions)\n"
    "# - \"etx_float\", a floating point  ETX with exponential aging\n"
    "# - \"etx_fpm\", same as ext_float, but with integer arithmetic\n"
    "# - \"etx_ff\" (ETX freifunk), an etx variant which use all OLSR\n"
    "#   traffic (instead of only hellos) for ETX calculation\n"
    "# - \"etx_ffeth\", an incompatible variant of etx_ff that allows\n"
    "#   ethernet links with ETX 0.1.\n"
    "# (default is \"%s\")\n"
    "\n", DEF_LQ_ALGORITHM);
  abuf_appendf(out, "%sLinkQualityAlgorithm    \"%s\"\n",
      cnf->lq_algorithm == NULL ? "# " : "",
      cnf->lq_algorithm == NULL ? DEF_LQ_ALGORITHM : cnf->lq_algorithm);
  abuf_appendf(out,
    "\n"
    "# Link quality aging factor (only for lq level 2)\n"
    "# Tuning parameter for etx_float and etx_fpm, smaller values\n"
    "# mean slower changes of ETX value. (allowed values are\n"
    "# between 0.01 and 1.0)\n"
    "# (default is %.2f)\n"
    "\n", (double)DEF_LQ_AGING);
  abuf_appendf(out, "%sLinkQualityAging %.2f\n",
      cnf->lq_aging == (float)DEF_LQ_AGING ? "# " : "",
      (double)cnf->lq_aging);
  abuf_appendf(out,
    "\n"
    "# Fisheye mechanism for TCs (0 meansoff, 1 means on)\n"
    "# (default is %u)\n"
    "\n", DEF_LQ_FISH);
  abuf_appendf(out, "%sLinkQualityFishEye  %d\n",
      cnf->lq_fish == DEF_LQ_FISH ? "# " : "",
      cnf->lq_fish);
  abuf_appendf(out,
    "\n"
    "#\n"
    "# NatThreshold\n"
    "#\n"
    "# (currently this is only in the freifunk firmware)\n"
    "# If the NAT-Endpoint (the preferred 0/0 HNA emitting node)\n"
    "# is to be changed, the ETX value of the current 0/0 is\n"
    "# multiplied with the NatThreshold value before being\n"
    "# compared to the new one.\n"
    "# The parameter can be a value between 0.1 and 1.0, but\n"
    "# should be close to 1.0 if changed.\n"
    "# WARNING: This parameter should not be used together with\n"
    "# the etx_ffeth metric !!\n"
    "# (default is %.1f)\n"
    "\n", (double)DEF_LQ_NAT_THRESH);
  abuf_appendf(out, "%sNatThreshold  %.1f\n",
      cnf->lq_nat_thresh == (float)DEF_LQ_NAT_THRESH ? "# " : "",
      (double)cnf->lq_nat_thresh);

  abuf_puts(out,
    "\n"
    "#############################################################\n"
    "### Configuration of the IPC to the windows GUI interface ###\n"
    "#############################################################\n"
    "\n"
    "IpcConnect\n"
    "{\n"
    "     # Determines how many simultaneously\n"
    "     # IPC connections that will be allowed\n"
    "     # Setting this to 0 disables IPC\n"
    "\n");
  abuf_appendf(out, "     %sMaxConnections  %d\n",
      cnf->ipc_connections == DEF_IPC_CONNECTIONS ? "# " : "",
      cnf->ipc_connections);
  abuf_puts(out,
    "\n"
    "     # By default only 127.0.0.1 is allowed\n"
    "     # to connect. Here allowed hosts and networks can\n"
    "     # be added\n"
    "\n");
  if (!ipc_nets)
    abuf_puts(out,
      "     # Host            127.0.0.1\n"
      "     # Host            10.0.0.5\n"
      "     # Net             192.168.1.0 255.255.255.0\n");
  else
    while (ipc_nets) {
      if (ipc_nets->net.prefix_len == olsr_cnf->maxplen) {
        abuf_appendf(out, "    Host %s\n", olsr_ip_to_string(&ipbuf, &ipc_nets->net.prefix));
      } else {
        abuf_appendf(out, "    Net  %s\n", olsr_ip_prefix_to_string(&ipc_nets->net));
      }
      ipc_nets = ipc_nets->next;
    }
  abuf_puts(out,
    "}\n"
    "\n"
    "#####################################\n"
    "### Example plugin configurations ###\n"
    "#####################################\n"
    "# Olsrd plugins to load\n"
    "# This must be the absolute path to the file\n"
    "# or the loader will use the following scheme:\n"
    "# - Try the paths in the LD_LIBRARY_PATH\n"
    "#   environment variable.\n"
    "# - The list of libraries cached in /etc/ld.so.cache\n"
    "# - /lib, followed by /usr/lib\n"
    "#\n"
    "\n"
    "# Check whether a plugin is available for your operating system.\n"
    "# Each plugin should have a README file in it's lib subfolder.\n"
    "\n");

  while (plugins) {
    abuf_appendf(out, "LoadPlugin \"%s\" {\n", plugins->name);
    pl_param = plugins->params;
    while (pl_param) {
      abuf_appendf(out, "    PlParam \"%s\" \"%s\"\n", pl_param->key, pl_param->value);
      pl_param = pl_param->next;
    }
    abuf_puts(out, "}\n"
        "\n");
    plugins = plugins->next;
  }

  abuf_puts(out,
    "#############################################\n"
    "### OLSRD default interface configuration ###\n"
    "#############################################\n"
    "# the default interface section can have the same values as the following\n"
    "# interface configuration. It will allow you so set common options for all\n"
    "# interfaces.\n"
    "\n"
    "InterfaceDefaults\n");
  olsrd_write_if_autobuf(out, cnf, cnf->interface_defaults, false);
  abuf_puts(out,
    "\n"
    "######################################\n"
    "### OLSRd Interfaces configuration ###\n"
    "######################################\n"
    "# Multiple interfaces can be specified for a single configuration block, format:\n"
    "#   Interface \"<OLSRd-Interface1>\" \"<OLSRd-Interface2>\"\n"
    "#\n"
    "# Multiple configuration blocks can be specified.\n"
    "\n");
  first = true;
  while (interf) {
    abuf_appendf(out, "Interface \"%s\"\n", interf->name);
    olsrd_write_if_autobuf(out, cnf, interf->cnf, first);

    first = false;
    interf = interf->next;
  }

  abuf_puts(out,
      "\n"
      "# END AUTOGENERATED CONFIG\n");
}
/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */
