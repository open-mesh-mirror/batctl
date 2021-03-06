// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Sven Eckelmann <sven@narfation.org
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "main.h"

#include "genl_json.h"

static struct json_query_data batctl_json_query_mcast_flags = {
	.nlm_flags = NLM_F_DUMP,
	.cmd = BATADV_CMD_GET_MCAST_FLAGS,
};

COMMAND_NAMED(JSON_MIF, mcast_flags_json, "mfj", handle_json_query,
	      COMMAND_FLAG_MESH_IFACE | COMMAND_FLAG_NETLINK,
	      &batctl_json_query_mcast_flags, "");
