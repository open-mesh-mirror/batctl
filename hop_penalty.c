// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "main.h"
#include "sys.h"

static struct hop_penalty_data {
	uint8_t hop_penalty;
} hop_penalty;

static int parse_hop_penalty(struct state *state, int argc, char *argv[])
{
	struct settings_data *settings = state->cmd->arg;
	struct hop_penalty_data *data = settings->data;
	char *endptr;

	if (argc != 2) {
		fprintf(stderr, "Error - incorrect number of arguments (expected 1)\n");
		return -EINVAL;
	}

	data->hop_penalty = strtoul(argv[1], &endptr, 0);
	if (!endptr || *endptr != '\0') {
		fprintf(stderr, "Error - the supplied argument is invalid: %s\n", argv[1]);
		return -EINVAL;
	}

	return 0;
}

static int print_hop_penalty(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *ghdr;
	int *result = arg;

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (!attrs[BATADV_ATTR_HOP_PENALTY])
		return NL_OK;

	printf("%u\n", nla_get_u8(attrs[BATADV_ATTR_HOP_PENALTY]));

	*result = 0;
	return NL_STOP;
}

static int get_hop_penalty(struct state *state)
{
	return sys_simple_nlquery(state, BATADV_CMD_GET_MESH,
				  NULL, print_hop_penalty);
}

static int set_attrs_hop_penalty(struct nl_msg *msg, void *arg)
{
	struct state *state = arg;
	struct settings_data *settings = state->cmd->arg;
	struct hop_penalty_data *data = settings->data;

	nla_put_u8(msg, BATADV_ATTR_HOP_PENALTY, data->hop_penalty);

	return 0;
}

static int set_hop_penalty(struct state *state)
{
	return sys_simple_nlquery(state, BATADV_CMD_SET_MESH,
				  set_attrs_hop_penalty, NULL);
}

static struct settings_data batctl_settings_hop_penalty = {
	.sysfs_name = "hop_penalty",
	.data = &hop_penalty,
	.parse = parse_hop_penalty,
	.netlink_get = get_hop_penalty,
	.netlink_set = set_hop_penalty,
};

COMMAND_NAMED(SUBCOMMAND, hop_penalty, "hp", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE | COMMAND_FLAG_NETLINK,
	      &batctl_settings_hop_penalty,
	      "[penalty]         \tdisplay or modify hop_penalty setting");
