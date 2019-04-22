/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
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
#define DEBUG_ROUTING_ALGOS "routing_algos"

struct debug_table_data {
	const char *debugfs_name;
	size_t header_lines;
	int (*netlink_fn)(struct state *state, char *hard_iface, int read_opt,
			 float orig_timeout, float watch_interval);
	unsigned int option_unicast_only:1;
	unsigned int option_multicast_only:1;
	unsigned int option_timeout_interval:1;
	unsigned int option_orig_iface:1;
};

int handle_debug_table(struct state *state, int argc, char **argv);

#endif
