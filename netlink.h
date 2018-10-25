/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2009-2018  B.A.T.M.A.N. contributors:
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
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef _BATCTL_NETLINK_H
#define _BATCTL_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stdint.h>

struct state;

struct print_opts {
	int read_opt;
	float orig_timeout;
	float watch_interval;
	nl_recvmsg_msg_cb_t callback;
	char *remaining_header;
	const char *static_header;
	uint8_t nl_cmd;
};

struct ether_addr;

int netlink_create(struct state *state);
void netlink_destroy(struct state *state);

int netlink_print_routing_algos(void);

char *netlink_get_info(int ifindex, uint8_t nl_cmd, const char *header);
int translate_mac_netlink(const char *mesh_iface, const struct ether_addr *mac,
			  struct ether_addr *mac_out);
int get_nexthop_netlink(const char *mesh_iface, const struct ether_addr *mac,
			uint8_t *nexthop, char *ifname);
int get_primarymac_netlink(const char *mesh_iface, uint8_t *primarymac);

extern struct nla_policy batadv_netlink_policy[];

int missing_mandatory_attrs(struct nlattr *attrs[], const int mandatory[],
			    int num);
int netlink_print_common(struct state *state, char *orig_iface, int read_opt,
			 float orig_timeout, float watch_interval,
			 const char *header, uint8_t nl_cmd,
			 nl_recvmsg_msg_cb_t callback);

extern char algo_name_buf[256];
extern int last_err;
extern int64_t mcast_flags;
extern int64_t mcast_flags_priv;

#endif /* _BATCTL_NETLINK_H */
