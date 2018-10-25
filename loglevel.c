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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "functions.h"
#include "main.h"
#include "sys.h"

static void log_level_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] loglevel [parameters] [level[ level[ level]]...]\n");
	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -h print this help\n");
	fprintf(stderr, "levels:\n");
	fprintf(stderr, " \t none    Debug logging is disabled\n");
	fprintf(stderr, " \t all     Print messages from all below\n");
	fprintf(stderr, " \t batman  Messages related to routing / flooding / broadcasting\n");
	fprintf(stderr, " \t routes  Messages related to route added / changed / deleted\n");
	fprintf(stderr, " \t tt      Messages related to translation table operations\n");
	fprintf(stderr, " \t bla     Messages related to bridge loop avoidance\n");
	fprintf(stderr, " \t dat     Messages related to arp snooping and distributed arp table\n");
	fprintf(stderr, " \t nc      Messages related to network coding\n");
	fprintf(stderr, " \t mcast   Messages related to multicast\n");
	fprintf(stderr, " \t tp      Messages related to throughput meter\n");
}

int loglevel(char *mesh_iface, int argc, char **argv)
{
	int optchar, res = EXIT_FAILURE;
	int log_level = 0;
	char *path_buff;
	char str[4];
	int i;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			log_level_usage();
			return EXIT_SUCCESS;
		default:
			log_level_usage();
			return EXIT_FAILURE;
		}
	}

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		fprintf(stderr, "Error - could not allocate path buffer: out of memory ?\n");
		return EXIT_FAILURE;
	}

	snprintf(path_buff, PATH_BUFF_LEN, SYS_BATIF_PATH_FMT, mesh_iface);

	if (argc != 1) {
		check_root_or_die("batctl loglevel");

		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "none") == 0) {
				log_level = 0;
				break;
			} else if (strcmp(argv[i], "all") == 0) {
				log_level = 255;
				break;
			} else if (strcmp(argv[i], "batman") == 0)
				log_level |= BIT(0);
			else if (strcmp(argv[i], "routes") == 0)
				log_level |= BIT(1);
			else if (strcmp(argv[i], "tt") == 0)
				log_level |= BIT(2);
			else if (strcmp(argv[i], "bla") == 0)
				log_level |= BIT(3);
			else if (strcmp(argv[i], "dat") == 0)
				log_level |= BIT(4);
			else if (strcmp(argv[i], "nc") == 0)
				log_level |= BIT(5);
			else if (strcmp(argv[i], "mcast") == 0)
				log_level |= BIT(6);
			else if (strcmp(argv[i], "tp") == 0)
				log_level |= BIT(7);
			else {
				log_level_usage();
				goto out;
			}
		}

		snprintf(str, sizeof(str), "%i", log_level);
		res = write_file(path_buff, SYS_LOG_LEVEL, str, NULL);
		goto out;
	}

	res = read_file(path_buff, SYS_LOG_LEVEL, USE_READ_BUFF, 0, 0, 0);

	if (res != EXIT_SUCCESS)
		goto out;

	log_level = strtol(line_ptr, (char **) NULL, 10);

	printf("[%c] %s (%s)\n", (!log_level) ? 'x' : ' ',
	       "all debug output disabled", "none");
	printf("[%c] %s (%s)\n", (log_level & BIT(0)) ? 'x' : ' ',
	       "messages related to routing / flooding / broadcasting",
	       "batman");
	printf("[%c] %s (%s)\n", (log_level & BIT(1)) ? 'x' : ' ',
	       "messages related to route added / changed / deleted", "routes");
	printf("[%c] %s (%s)\n", (log_level & BIT(2)) ? 'x' : ' ',
	       "messages related to translation table operations", "tt");
	printf("[%c] %s (%s)\n", (log_level & BIT(3)) ? 'x' : ' ',
	       "messages related to bridge loop avoidance", "bla");
	printf("[%c] %s (%s)\n", (log_level & BIT(4)) ? 'x' : ' ',
	       "messages related to arp snooping and distributed arp table", "dat");
	printf("[%c] %s (%s)\n", (log_level & BIT(5)) ? 'x' : ' ',
	       "messages related to network coding", "nc");
	printf("[%c] %s (%s)\n", (log_level & BIT(6)) ? 'x' : ' ',
	       "messages related to multicast", "mcast");
	printf("[%c] %s (%s)\n", (log_level & BIT(7)) ? 'x' : ' ',
	       "messages related to throughput meter", "tp");

out:
	free(path_buff);
	return res;
}
