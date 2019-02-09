// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
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

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "batman_adv.h"
#include "functions.h"
#include "main.h"
#include "netlink.h"
#include "sys.h"

#define SYS_GW_MODE		"gw_mode"
#define SYS_GW_SEL		"gw_sel_class"
#define SYS_GW_BW		"gw_bandwidth"

static struct gw_data {
	uint8_t bandwidth_down_found:1;
	uint8_t bandwidth_up_found:1;
	uint8_t sel_class_found:1;
	uint8_t mode;
	uint32_t bandwidth_down;
	uint32_t bandwidth_up;
	uint32_t sel_class;
} gw_globals;

static void gw_mode_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] gw_mode [mode] [sel_class|bandwidth]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, " \t -h print this help\n");
}

static bool is_throughput_select_class(struct state *state)
{
	char algoname[32];
	int ret;

	ret = get_algoname(state->mesh_iface, algoname, sizeof(algoname));

	/* no algo name -> assume that it is a pre-B.A.T.M.A.N. V version */
	if (ret < 0)
		return false;

	if (strcmp(algoname, "BATMAN_V") == 0)
		return true;

	return false;
}
static int parse_gw_limit(char *buff)
{
	char *slash_ptr;
	bool ret;

	slash_ptr = strchr(buff, '/');
	if (slash_ptr)
		*slash_ptr = 0;

	ret = parse_throughput(buff, "download gateway speed",
				&gw_globals.bandwidth_down);
	if (!ret)
		return -EINVAL;

	gw_globals.bandwidth_down_found = 1;

	/* we also got some upload info */
	if (slash_ptr) {
		ret = parse_throughput(slash_ptr + 1, "upload gateway speed",
				       &gw_globals.bandwidth_up);
		if (!ret)
			return -EINVAL;

		gw_globals.bandwidth_up_found = 1;
	}

	return 0;
}

static int parse_gw(struct state *state, int argc, char *argv[])
{
	char buff[256];
	char *endptr;
	int ret;

	if (argc != 2 && argc != 3) {
		fprintf(stderr, "Error - incorrect number of arguments (expected 1/2)\n");
		return -EINVAL;
	}

	if (strcmp(argv[1], "client") == 0) {
		gw_globals.mode = BATADV_GW_MODE_CLIENT;
	} else if (strcmp(argv[1], "server") == 0) {
		gw_globals.mode = BATADV_GW_MODE_SERVER;
	} else if (strcmp(argv[1], "off") == 0) {
		gw_globals.mode = BATADV_GW_MODE_OFF;
	} else {
		fprintf(stderr, "Error - the supplied argument is invalid: %s\n", argv[1]);
		fprintf(stderr, "The following values are allowed:\n");
		fprintf(stderr, " * off\n");
		fprintf(stderr, " * client\n");
		fprintf(stderr, " * server\n");

		return -EINVAL;
	}

	if (argc <= 2)
		return 0;

	strncpy(buff, argv[2], sizeof(buff));
	buff[sizeof(buff) - 1] = '\0';

	switch (gw_globals.mode) {
	case  BATADV_GW_MODE_OFF:
		fprintf(stderr, "Error - unexpected argument for mode \"off\": %s\n", argv[2]);
		return -EINVAL;
	case BATADV_GW_MODE_CLIENT:
		if (is_throughput_select_class(state)) {
			if (!parse_throughput(buff, "sel_class",
					      &gw_globals.sel_class))
				return -EINVAL;
		} else {
			gw_globals.sel_class = strtoul(buff, &endptr, 0);
			if (!endptr || *endptr != '\0') {
				fprintf(stderr, "Error - unexpected argument for mode \"client\": %s\n", buff);
				return -EINVAL;
			}
		}

		gw_globals.sel_class_found = 1;
		break;
	case BATADV_GW_MODE_SERVER:
		ret = parse_gw_limit(buff);
		if (ret < 0)
			return ret;
		break;
	}

	return 0;
}

static int gw_mode(struct state *state, int argc, char **argv)
{
	int optchar, res = EXIT_FAILURE;
	char *path_buff, gw_mode;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			gw_mode_usage();
			return EXIT_SUCCESS;
		default:
			gw_mode_usage();
			return EXIT_FAILURE;
		}
	}

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		fprintf(stderr, "Error - could not allocate path buffer: out of memory ?\n");
		return EXIT_FAILURE;
	}

	snprintf(path_buff, PATH_BUFF_LEN, SYS_BATIF_PATH_FMT, state->mesh_iface);

	if (argc == 1) {
		res = read_file(path_buff, SYS_GW_MODE, USE_READ_BUFF, 0, 0, 0);

		if (res != EXIT_SUCCESS)
			goto out;

		if (line_ptr[strlen(line_ptr) - 1] == '\n')
			line_ptr[strlen(line_ptr) - 1] = '\0';

		if (strcmp(line_ptr, "client") == 0)
			gw_mode = BATADV_GW_MODE_CLIENT;
		else if (strcmp(line_ptr, "server") == 0)
			gw_mode = BATADV_GW_MODE_SERVER;
		else
			gw_mode = BATADV_GW_MODE_OFF;

		free(line_ptr);
		line_ptr = NULL;

		switch (gw_mode) {
		case BATADV_GW_MODE_CLIENT:
			res = read_file(path_buff, SYS_GW_SEL, USE_READ_BUFF, 0, 0, 0);
			break;
		case BATADV_GW_MODE_SERVER:
			res = read_file(path_buff, SYS_GW_BW, USE_READ_BUFF, 0, 0, 0);
			break;
		default:
			printf("off\n");
			goto out;
		}

		if (res != EXIT_SUCCESS)
			goto out;

		if (line_ptr[strlen(line_ptr) - 1] == '\n')
			line_ptr[strlen(line_ptr) - 1] = '\0';

		switch (gw_mode) {
		case BATADV_GW_MODE_CLIENT:
			printf("client (selection class: %s)\n", line_ptr);
			break;
		case BATADV_GW_MODE_SERVER:
			printf("server (announced bw: %s)\n", line_ptr);
			break;
		default:
			goto out;
		}

		free(line_ptr);
		line_ptr = NULL;
		goto out;
	}

	check_root_or_die("batctl gw_mode");

	res = parse_gw(state, argc, argv);
	if (res < 0) {
		res = EXIT_FAILURE;
		goto out;
	}

	res = write_file(path_buff, SYS_GW_MODE, argv[1], NULL);
	if (res != EXIT_SUCCESS)
		goto out;

	if (argc == 2)
		goto out;

	switch (gw_globals.mode) {
	case BATADV_GW_MODE_CLIENT:
		res = write_file(path_buff, SYS_GW_SEL, argv[2], NULL);
		break;
	case BATADV_GW_MODE_SERVER:
		res = write_file(path_buff, SYS_GW_BW, argv[2], NULL);
		break;
	}

	goto out;

out:
	free(path_buff);
	return res;
}

COMMAND(SUBCOMMAND, gw_mode, "gw", COMMAND_FLAG_MESH_IFACE, NULL,
	"[mode]            \tdisplay or modify the gateway mode");
