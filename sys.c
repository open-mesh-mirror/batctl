// SPDX-License-Identifier: GPL-2.0
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


#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "main.h"
#include "sys.h"
#include "functions.h"
#include "debug.h"

const char *sysfs_param_enable[] = {
	"enable",
	"disable",
	"1",
	"0",
	NULL,
};

const char *sysfs_param_server[] = {
	"off",
	"client",
	"server",
	NULL,
};

static void settings_usage(struct state *state)
{
	fprintf(stderr, "Usage: batctl [options] %s|%s [parameters] %s\n",
		state->cmd->name, state->cmd->abbr, state->cmd->usage);

	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -h print this help\n");
}

int handle_sys_setting(struct state *state, int argc, char **argv)
{
	struct settings_data *settings = state->cmd->arg;
	int vid, optchar, res = EXIT_FAILURE;
	char *path_buff, *base_dev = NULL;
	const char **ptr;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			settings_usage(state);
			return EXIT_SUCCESS;
		default:
			settings_usage(state);
			return EXIT_FAILURE;
		}
	}

	/* prepare the classic path */
	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		fprintf(stderr, "Error - could not allocate path buffer: out of memory ?\n");
		return EXIT_FAILURE;
	}

	snprintf(path_buff, PATH_BUFF_LEN, SYS_BATIF_PATH_FMT, state->mesh_iface);

	/* if the specified interface is a VLAN then change the path to point
	 * to the proper "vlan%{vid}" subfolder in the sysfs tree.
	 */
	vid = vlan_get_link(state->mesh_iface, &base_dev);
	if (vid >= 0)
		snprintf(path_buff, PATH_BUFF_LEN, SYS_VLAN_PATH, base_dev, vid);

	if (argc == 1) {
		res = read_file(path_buff, settings->sysfs_name,
				NO_FLAGS, 0, 0, 0);
		goto out;
	}

	check_root_or_die("batctl");

	if (!settings->params)
		goto write_file;

	ptr = settings->params;
	while (*ptr) {
		if (strcmp(*ptr, argv[1]) == 0)
			goto write_file;

		ptr++;
	}

	fprintf(stderr, "Error - the supplied argument is invalid: %s\n", argv[1]);
	fprintf(stderr, "The following values are allowed:\n");

	ptr = settings->params;
	while (*ptr) {
		fprintf(stderr, " * %s\n", *ptr);
		ptr++;
	}

	goto out;

write_file:
	res = write_file(path_buff, settings->sysfs_name,
			 argv[1], argc > 2 ? argv[2] : NULL);

out:
	free(path_buff);
	free(base_dev);
	return res;
}

static struct settings_data batctl_settings_orig_interval = {
	.sysfs_name = "orig_interval",
	.params = NULL,
};

COMMAND_NAMED(SUBCOMMAND, orig_interval, "it", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE, &batctl_settings_orig_interval,
	      "[interval]        \tdisplay or modify orig_interval setting");

static struct settings_data batctl_settings_fragmentation = {
	.sysfs_name = "fragmentation",
	.params = sysfs_param_enable,
};

COMMAND_NAMED(SUBCOMMAND, fragmentation, "f", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE, &batctl_settings_fragmentation,
	      "[0|1]             \tdisplay or modify fragmentation setting");

static struct settings_data batctl_settings_network_coding = {
	.sysfs_name = SYS_NETWORK_CODING,
	.params = sysfs_param_enable,
};

COMMAND_NAMED(SUBCOMMAND, network_coding, "nc", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE, &batctl_settings_network_coding,
	      "[0|1]             \tdisplay or modify network_coding setting");

static struct settings_data batctl_settings_isolation_mark = {
	.sysfs_name = "isolation_mark",
	.params = NULL,
};

COMMAND_NAMED(SUBCOMMAND, isolation_mark, "mark", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE, &batctl_settings_isolation_mark,
	      "[mark]            \tdisplay or modify isolation_mark setting");

static struct settings_data batctl_settings_multicast_mode = {
	.sysfs_name = SYS_MULTICAST_MODE,
	.params = sysfs_param_enable,
};

COMMAND_NAMED(SUBCOMMAND, multicast_mode, "mm", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE, &batctl_settings_multicast_mode,
	      "[0|1]             \tdisplay or modify multicast_mode setting");
