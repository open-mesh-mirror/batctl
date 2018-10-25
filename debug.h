/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2009-2018  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
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

#ifndef _BATCTL_DEBUG_H
#define _BATCTL_DEBUG_H

#include <stddef.h>
#include "main.h"

#define DEBUG_BATIF_PATH_FMT "%s/batman_adv/%s"
#define DEBUG_TRANSTABLE_GLOBAL "transtable_global"
#define DEBUG_BACKBONETABLE "bla_backbone_table"
#define DEBUG_CLAIMTABLE "bla_claim_table"
#define DEBUG_DAT_CACHE "dat_cache"
#define DEBUG_NC_NODES "nc_nodes"
#define DEBUG_MCAST_FLAGS "mcast_flags"
#define DEBUG_LOG "log"
#define DEBUG_ROUTING_ALGOS "routing_algos"

struct debug_table_data {
	const char *debugfs_name;
	size_t header_lines;
	int (*netlink_fn)(struct state *state, char *hard_iface, int read_opt,
			 float orig_timeout, float watch_interval);
	unsigned int option_unicast_only:1;
	unsigned int option_multicast_only:1;
	unsigned int option_watch_interval:1;
	unsigned int option_orig_iface:1;
};

int handle_debug_table(struct state *state, int argc, char **argv);
int debug_print_routing_algos(void);

#endif
