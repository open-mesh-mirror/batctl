// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "debug.h"
#include "main.h"

static struct debug_table_data batctl_debug_table_nc_nodes = {
	.debugfs_name = DEBUG_NC_NODES,
	.header_lines = 0,
};

COMMAND_NAMED(DEBUGTABLE, nc_nodes, "nn", handle_debug_table,
	      COMMAND_FLAG_MESH_IFACE, &batctl_debug_table_nc_nodes, "");
