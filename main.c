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
#include "translate.h"
#include "traceroute.h"
#include "tcpdump.h"
#include "bisect_iv.h"
#include "vis.h"
#include "ioctl.h"
#include "functions.h"
#include <err.h>

char mesh_dfl_iface[] = "bat0";
char module_ver_path[] = "/sys/module/batman_adv/version";

void print_usage(void)
{
	int i, opt_indent;

	printf("Usage: batctl [options] command|debug table [parameters]\n");
	printf("options:\n");
	printf(" \t-m mesh interface (default 'bat0')\n");
	printf(" \t-h print this help (or 'batctl <command|debug table> -h' for the parameter help)\n");
	printf(" \t-v print version\n");
	printf("\n");

	printf("commands:\n");
	printf(" \tinterface|if               [add|del iface(s)]\tdisplay or modify the interface settings\n");
	for (i = 0; i < BATCTL_SETTINGS_NUM; i++) {
		printf(" \t%s|%s", batctl_settings[i].opt_long, batctl_settings[i].opt_short);
		opt_indent = strlen(batctl_settings[i].opt_long) + strlen(batctl_settings[i].opt_short);

		if (batctl_settings[i].params == sysfs_param_enable)
			printf("%*s                display or modify %s setting\n",
			       31 - opt_indent, "[0|1]", batctl_settings[i].opt_long);
		else if (batctl_settings[i].params == sysfs_param_server)
			printf("%*s      display or modify %s setting\n",
			       41 - opt_indent, "[client|server]", batctl_settings[i].opt_long);
		else
			printf("                                display or modify %s setting\n",
			       batctl_settings[i].opt_long);
	}
	printf(" \tloglevel|ll                [level]           \tdisplay or modify the log level\n");
	printf(" \tlog|l                                        \tread the log produced by the kernel module\n");
	printf(" \tgw_mode|gw                 [mode]            \tdisplay or modify the gateway mode\n");
	printf(" \tvis_data|vd                [dot|JSON]        \tdisplay the VIS data in dot or JSON format\n");
	printf("\n");

	printf("debug tables:                                   \tdisplay the corresponding debug table\n");
	for (i = 0; i < BATCTL_TABLE_NUM; i++)
		printf(" \t%s|%s\n", batctl_debug_tables[i].opt_long, batctl_debug_tables[i].opt_short);

	printf("\n");
	printf(" \tstatistics|s                                 \tprint mesh statistics\n");
	printf(" \tping|p                     <destination>     \tping another batman adv host via layer 2\n");
	printf(" \ttraceroute|tr              <destination>     \ttraceroute another batman adv host via layer 2\n");
	printf(" \ttcpdump|td                 <interface>       \ttcpdump layer 2 traffic on the given interface\n");
	printf(" \ttranslate|t                <destination>     \ttranslate a destination to the originator responsible for it\n");
#ifdef BATCTL_BISECT
	printf(" \tbisect_iv                  <file1> .. <fileN>\tanalyze given batman iv log files for routing stability\n");
#endif
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

		ret = read_file("", module_ver_path, USE_READ_BUFF | SILENCE_ERRORS, 0, 0, 0);
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
	if ((strncmp(argv[1], "bisect", strlen("bisect")) != 0) && ((getuid()) || (getgid()))) {
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

	} else if ((strcmp(argv[1], "vis_data") == 0) || (strcmp(argv[1], "vd") == 0)) {

		ret = vis_data(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "gw_mode") == 0) || (strcmp(argv[1], "gw") == 0)) {

		ret = handle_gw_setting(mesh_iface, argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "statistics") == 0) || (strcmp(argv[1], "s") == 0)) {

		ret = ioctl_statistics_get(mesh_iface);

	} else if ((strcmp(argv[1], "translate") == 0) || (strcmp(argv[1], "t") == 0)) {

		ret = translate(mesh_iface, argc - 1, argv + 1);

#ifdef BATCTL_BISECT
	} else if ((strcmp(argv[1], "bisect_iv") == 0)) {

		ret = bisect_iv(argc - 1, argv + 1);
#endif

	} else {

		for (i = 0; i < BATCTL_SETTINGS_NUM; i++) {
			if ((strcmp(argv[1], batctl_settings[i].opt_long) != 0) &&
			    (strcmp(argv[1], batctl_settings[i].opt_short) != 0))
				continue;

			ret = handle_sys_setting(mesh_iface, i, argc - 1, argv + 1);
			goto out;
		}

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
