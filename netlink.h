/*
 * Copyright (C) 2009-2016  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>, Andrew Lunn <andrew@lunn.ch>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#ifndef _BATCTL_NETLINK_H
#define _BATCTL_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

struct ether_addr;

int netlink_print_routing_algos(void);
int netlink_print_originators(char *mesh_iface, char *orig_iface, int read_opt,
			      float orig_timeout, float watch_interval);
int netlink_print_neighbors(char *mesh_iface, char *orig_iface, int read_opt,
			    float orig_timeout, float watch_interval);
int netlink_print_gateways(char *mesh_iface, char *orig_iface, int read_opt,
			   float orig_timeout, float watch_interval);
int netlink_print_transglobal(char *mesh_iface, char *orig_iface, int read_opt,
			      float orig_timeout, float watch_interval);
int netlink_print_translocal(char *mesh_iface, char *orig_iface, int read_opt,
			     float orig_timeout, float watch_interval);
int netlink_print_gateways(char *mesh_iface, char *orig_iface, int read_opt,
			   float orig_timeout, float watch_interval);
int netlink_print_bla_claim(char *mesh_iface, char *orig_iface, int read_opt,
			    float orig_timeout, float watch_interval);
int netlink_print_bla_backbone(char *mesh_iface, char *orig_iface, int read_opt,
			       float orig_timeout, float watch_interval);

int translate_mac_netlink(const char *mesh_iface, const struct ether_addr *mac,
			  struct ether_addr *mac_out);

extern struct nla_policy batadv_netlink_policy[];

#endif /* _BATCTL_NETLINK_H */
