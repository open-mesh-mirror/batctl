// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "debug.h"
#include "debugfs.h"
#include "functions.h"

static void log_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] log [parameters]\n");
	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -h print this help\n");
	fprintf(stderr, " \t -n don't replace mac addresses with bat-host names\n");
}

static int log_print(struct state *state, int argc, char **argv)
{
	int optchar, res, read_opt = USE_BAT_HOSTS | LOG_MODE;
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;

	while ((optchar = getopt(argc, argv, "hn")) != -1) {
		switch (optchar) {
		case 'h':
			log_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			break;
		default:
			log_usage();
			return EXIT_FAILURE;
		}
	}

	check_root_or_die("batctl log");

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		fprintf(stderr, "Error - can't mount or find debugfs\n");
		return EXIT_FAILURE;
	}

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/", state->mesh_iface, full_path, sizeof(full_path));
	res = read_file(full_path, DEBUG_LOG, read_opt, 0, 0, 0);
	return res;
}

COMMAND_NAMED(SUBCOMMAND, log, "l", log_print, COMMAND_FLAG_MESH_IFACE, NULL,
	      "                  \tread the log produced by the kernel module");
