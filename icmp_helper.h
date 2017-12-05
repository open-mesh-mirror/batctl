/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2007-2017  B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <mareklindner@neomailbox.ch>
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

#ifndef _BATCTL_ICMP_HELPER_H
#define _BATCTL_ICMP_HELPER_H

#include "main.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <stddef.h>
#include <stdint.h>

#include "batadv_packet.h"
#include "list.h"

struct timeval;

struct icmp_interface {
	char name[IFNAMSIZ];
	uint8_t mac[ETH_ALEN];

	int sock;

	int mark;
	struct list_head list;
};

int icmp_interfaces_init(void);
int icmp_interface_write(const char *mesh_iface,
			 struct batadv_icmp_header *icmp_packet, size_t len);
void icmp_interfaces_clean(void);
ssize_t icmp_interface_read(struct batadv_icmp_header *icmp_packet, size_t len,
			    struct timeval *tv);

#endif
