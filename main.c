/*
 * Copyright (C) 2007-2012 B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <lindner_marek@yahoo.de>
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
 */



#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "main.h"
#include "sys.h"
#include "debug.h"
#include "ping.h"
#include "traceroute.h"
#include "tcpdump.h"
#include "bisect.h"
#include "vis.h"
#include "ioctl.h"
#include "functions.h"
#include <err.h>

char mesh_dfl_iface[] = "bat0";
char module_ver_path[] = "/sys/module/batman_adv/version";

void print_usage(void)
{
	int i;

	printf("Usage: batctl [options] command|debug table \n");
	printf("options:\n");
	printf(" \t-m mesh interface (default 'bat0')\n");
	printf(" \t-h print this help (or 'batctl <command|debug table> -h' for the specific help)\n");
	printf(" \t-v print version\n");
	printf("\n");

	printf("commands:\n");
	printf(" \tinterface|if               [add|del iface(s)]\tdisplay or modify the interface settings\n");
	printf(" \tinterval|it                [orig_interval]   \tdisplay or modify the originator interval (in ms)\n");
	printf(" \tloglevel|ll                [level]           \tdisplay or modify the log level\n");
	printf(" \tlog|l                                        \tread the log produced by the kernel module\n");
	printf(" \tgw_mode|gw                 [mode]            \tdisplay or modify the gateway mode\n");
	printf(" \tvis_mode|vm                [mode]            \tdisplay or modify the status of the VIS server\n");
	printf(" \tvis_data|vd                [dot|JSON]        \tdisplay the VIS data in dot or JSON format\n");
	printf(" \taggregation|ag             [0|1]             \tdisplay or modify the packet aggregation setting\n");
	printf(" \tbonding|b                  [0|1]             \tdisplay or modify the bonding mode setting\n");
	printf(" \tbridge_loop_avoidance|bl   [0|1]             \tdisplay or modify the bridge loop avoidance setting\n");
	printf(" \tfragmentation|f            [0|1]             \tdisplay or modify the fragmentation mode setting\n");
	printf(" \tap_isolation|ap            [0|1]             \tdisplay or modify the ap isolation mode setting\n");
	printf("\n");

	printf("debug tables:                                   \tdisplay the corresponding debug table\n");
	for (i = 0; i < BATCTL_TABLE_NUM; i++)
		printf(" \t%s|%s\n", batctl_debug_tables[i].opt_long, batctl_debug_tables[i].opt_short);

	printf("\n");
	printf(" \tstatistics|s                                 \tprint mesh statistics\n");
	printf(" \tping|p                     <destination>     \tping another batman adv host via layer 2\n");
	printf(" \ttraceroute|tr              <destination>     \ttraceroute another batman adv host via layer 2\n");
	printf(" \ttcpdump|td                 <interface>       \ttcpdump layer 2 traffic on the given interface\n");
	printf(" \tbisect                     <file1> .. <fileN>\tanalyze given log files for routing stability\n");
}

int main(int argc, char **argv)
{
	int i, ret = EXIT_FAILURE;
	char *mesh_iface = mesh_dfl_iface;

	if ((argc > 1) && (strcmp(argv[1], "-m") == 0)) {
		if (argc < 3) {
			printf("Error - the option '-m' needs a parameter\n");
			goto err;
		}

		mesh_iface = argv[2];

		argv += 2;
		argc -= 2;
	}

	if (argc < 2) {
		printf("Error - no command specified\n");
		goto err;
	}

	if (strcmp(argv[1], "-h") == 0)
		goto err;

	if (strcmp(argv[1], "-v") == 0) {
		printf("batctl %s [batman-adv: ", SOURCE_VERSION);

		ret = read_file("", module_ver_path, USE_READ_BUFF | SILENCE_ERRORS, 0, 0);
		if ((line_ptr) && (line_ptr[strlen(line_ptr) - 1] == '\n'))
			line_ptr[strlen(line_ptr) - 1] = '\0';

		if (ret == EXIT_SUCCESS)
			printf("%s]\n", line_ptr);
		else
			printf("module not loaded]\n");

		free(line_ptr);
		exit(EXIT_SUCCESS);
	}

	/* TODO: remove this generic check here and move it into the individual functions */
	/* check if user is root */
	if ((strcmp(argv[1], "bisect") != 0) && ((getuid()) || (getgid()))) {
		fprintf(stderr, "Error - you must be root to run '%s' !\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ((strcmp(argv[1], "ping") == 0) || (strcmp(argv[1], "p") == 0)) {

		ret = ping(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "traceroute") == 0) || (strcmp(argv[1], "tr") == 0)) {

		ret = traceroute(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "tcpdump") == 0) || (strcmp(argv[1], "td") == 0)) {

		ret = tcpdump(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "interface") == 0) || (strcmp(argv[1], "if") == 0)) {

		ret = interface(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "loglevel") == 0) || (strcmp(argv[1], "ll") == 0)) {

		ret = handle_loglevel(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "log") == 0) || (strcmp(argv[1], "l") == 0)) {

		ret = log_print(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "interval") == 0) || (strcmp(argv[1], "it") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_ORIG_INTERVAL, orig_interval_usage, NULL);

	} else if ((strcmp(argv[1], "vis_mode") == 0) || (strcmp(argv[1], "vm") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_VIS_MODE, vis_mode_usage, sysfs_param_server);

	} else if ((strcmp(argv[1], "vis_data") == 0) || (strcmp(argv[1], "vd") == 0)) {

		ret = vis_data(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "gw_mode") == 0) || (strcmp(argv[1], "gw") == 0)) {

		ret = handle_gw_setting(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "aggregation") == 0) || (strcmp(argv[1], "ag") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_AGGR, aggregation_usage, sysfs_param_enable);

	} else if ((strcmp(argv[1], "bonding") == 0) || (strcmp(argv[1], "b") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_BONDING, bonding_usage, sysfs_param_enable);

	} else if ((strcmp(argv[1], "bridge_loop_avoidance") == 0) || (strcmp(argv[1], "bl") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_BRIDGE_LOOP_AVOIDANCE, bridge_loop_avoidance_usage, sysfs_param_enable);

	} else if ((strcmp(argv[1], "fragmentation") == 0) || (strcmp(argv[1], "f") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_FRAG, fragmentation_usage, sysfs_param_enable);

	} else if ((strcmp(argv[1], "ap_isolation") == 0) || (strcmp(argv[1], "ap") == 0)) {

		ret = handle_sys_setting(mesh_iface, argc - 1, argv + 1,
					 SYS_AP_ISOLA, ap_isolation_usage, sysfs_param_enable);

	} else if ((strcmp(argv[1], "statistics") == 0) || (strcmp(argv[1], "s") == 0)) {

		ret = ioctl_statistics_get(mesh_iface);

	} else if ((strcmp(argv[1], "bisect") == 0)) {

		ret = bisect(argc - 1, argv + 1);

	} else {

		for (i = 0; i < BATCTL_TABLE_NUM; i++) {
			if ((strcmp(argv[1], batctl_debug_tables[i].opt_long) != 0) &&
			    (strcmp(argv[1], batctl_debug_tables[i].opt_short) != 0))
				continue;

			ret = handle_debug_table(mesh_iface, i, argc - 1, argv + 1);
			goto out;
		}

		printf("Error - no valid command or debug table specified: %s\n", argv[1]);
		print_usage();
	}

out:
	return ret;

err:
	print_usage();
	exit(EXIT_FAILURE);
}
