/*
 * Copyright (C) 2007-2009 B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <a.langer@q-dsl.de>, Marek Lindner <lindner_marek@yahoo.de>
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
#include "proc.h"
#include "sys.h"
#include "ping.h"
#include "traceroute.h"
#include "tcpdump.h"
#include "bisect.h"


void print_usage(void) {
	printf("Usage: batctl [options] commands \n");
	printf("commands:\n");
	printf(" \tinterface|if  [none|interface]  \tdisplay or modify the interface settings\n");
	printf(" \toriginators|o                   \tdisplay the originator table\n");
	printf(" \tinterval|it   [orig_interval]   \tdisplay or modify the originator interval in ms\n");
	printf(" \tloglevel|ll   [level]           \tdisplay or modify the log level\n");
	printf(" \tlog|l                           \tread the log produced by the kernel module\n");
	printf(" \ttranslocal|tl                   \tdisplay the local translation table\n");
	printf(" \ttransglobal|tg                  \tdisplay the global translation table\n");
	printf(" \tvisformat|vf  [format]          \tdisplay or modify the vis output format\n");
	printf(" \taggregation|ag   [0|1]          \tdisplay or modify the packet aggregation setting\n");
	printf("\n");
	printf(" \tping|p        <destination>     \tping another batman adv host via layer 2\n");
	printf(" \ttraceroute|tr <destination>     \ttraceroute another batman adv host via layer 2\n");
	printf(" \ttcpdump|td    <interface>       \ttcpdump layer 2 traffic on the given interface\n");
	printf(" \tbisect        <file1> .. <fileN>\tanalyze given log files for routing stability\n");
	printf("options:\n");
	printf(" \t-h print this help (or 'batctl <command> -h' for the command specific help)\n");
	printf(" \t-v print version\n");
}

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;

	if ((argc < 2) || (strcmp(argv[1], "-h") == 0)) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "-v") == 0) {
		printf("batctl %s%s\n", SOURCE_VERSION, (strlen(REVISION_VERSION) > 3 ? REVISION_VERSION : ""));
		exit(EXIT_SUCCESS);
	}

	/* check if user is root */
	if ((strcmp(argv[1], "bisect") != 0) && ((getuid()) || (getgid()))) {
		fprintf(stderr, "Error - you must be root to run '%s' !\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ((strcmp(argv[1], "ping") == 0) || (strcmp(argv[1], "p") == 0)) {

		ret = ping(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "traceroute") == 0) || (strcmp(argv[1], "tr") == 0)) {

		ret = traceroute(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "tcpdump") == 0) || (strcmp(argv[1], "td") == 0)) {

		ret = tcpdump(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "interface") == 0) || (strcmp(argv[1], "if") == 0)) {

		ret = interface(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "originators") == 0) || (strcmp(argv[1], "o") == 0)) {

		ret = handle_table(argc - 1, argv + 1, PROC_ORIGINATORS, originators_usage);

	} else if ((strcmp(argv[1], "translocal") == 0) || (strcmp(argv[1], "tl") == 0)) {

		ret = handle_table(argc - 1, argv + 1, PROC_TRANSTABLE_LOCAL, trans_local_usage);

	} else if ((strcmp(argv[1], "transglobal") == 0) || (strcmp(argv[1], "tg") == 0)) {

		ret = handle_table(argc - 1, argv + 1, PROC_TRANSTABLE_GLOBAL, trans_global_usage);

	} else if ((strcmp(argv[1], "loglevel") == 0) || (strcmp(argv[1], "ll") == 0)) {

		ret = handle_loglevel(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "log") == 0) || (strcmp(argv[1], "l") == 0)) {

		ret = log_print(argc - 1, argv + 1);

	} else if ((strcmp(argv[1], "interval") == 0) || (strcmp(argv[1], "it") == 0)) {

		ret = handle_proc_setting(argc - 1, argv + 1, PROC_ORIG_INTERVAL, orig_interval_usage);

	} else if ((strcmp(argv[1], "visformat") == 0) || (strcmp(argv[1], "vf") == 0)) {

		ret = handle_proc_setting(argc - 1, argv + 1, PROC_VIS_FORMAT, vis_format_usage);

	} else if ((strcmp(argv[1], "aggregation") == 0) || (strcmp(argv[1], "ag") == 0)) {

		ret = handle_proc_setting(argc - 1, argv + 1, PROC_AGGR, aggregation_usage);

	} else if ((strcmp(argv[1], "bisect") == 0)) {

		ret = bisect(argc - 1, argv + 1);

	} else {
		print_usage();
	}

	return ret;
}
