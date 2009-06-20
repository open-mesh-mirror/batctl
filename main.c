/* Copyright (C) 2007-2009 B.A.T.M.A.N. contributors:
 * Andreas Langer <a.langer@q-dsl.de>
 * Marek Lindner <lindner_marek@yahoo.de>
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

#include "main.h"
#include "ping.h"
#include "traceroute.h"
#include "tcpdump.h"


void print_usage() {
	printf("Usage: batctl [options] commands \n");
	printf("commands:\n");
	printf(" \tping|p        <destination> \tping another batman adv host via layer 2\n");
	printf(" \ttraceroute|tr <destination> \ttraceroute another batman adv host via layer 2\n");
	printf(" \ttcpdump|td    <interface>   \ttcpdump layer 2 traffic on the given interface\n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -v print version\n");
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
	if ((getuid()) || (getgid())) {
		fprintf(stderr, "Error - you must be root to run '%s' !\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "ping") == 0 || strcmp(argv[1], "p") == 0 ) {
		/* call ping main function */
		ret = ping(argc - 1, argv + 1);

	} else if(strcmp(argv[1], "traceroute") == 0 || strcmp(argv[1], "tr") == 0  ) {
		/* call trace main function */
		ret = traceroute(argc - 1, argv + 1);

	} else if( strcmp(argv[1], "tcpdump") == 0 || strcmp(argv[1], "td") == 0  ) {
		/* call trace main function */
		ret = tcpdump(argc - 1, argv + 1);

	} else {
		print_usage();
	}

	return ret;
}
