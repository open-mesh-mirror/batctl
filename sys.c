/*
 * Copyright (C) 2009 B.A.T.M.A.N. contributors:
 *
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


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "sys.h"
#include "functions.h"


static void log_usage(void)
{
	printf("Usage: batctl [options] log [logfile]\n");
	printf("Note: if no logfile was specified stdin is read");
	printf("options:\n");
	printf(" \t -b batch mode - read the log file once and quit\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

int log_print(int argc, char **argv)
{
	int optchar, read_opt = CONT_READ | USE_BAT_HOSTS | LOG_MODE;
	int found_args = 1;

	while ((optchar = getopt(argc, argv, "bhn")) != -1) {
		switch (optchar) {
		case 'b':
			read_opt &= ~CONT_READ;
			found_args += 1;
			break;
		case 'h':
			log_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		default:
			log_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc > found_args)
		return read_file("", argv[found_args], read_opt);
	else
		return read_file("", "/dev/stdin", read_opt);
}

static void log_level_usage(void)
{
	printf("Usage: batctl [options] loglevel \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int handle_loglevel(int argc, char **argv)
{
	int optchar, res;

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

	if (argc != 1) {
		res = write_file(SYS_ROOT_PATH, SYS_LOG_LEVEL, argv[1]);
		goto out;
	}

	res = read_file(SYS_ROOT_PATH, SYS_LOG_LEVEL, SINGLE_READ | USE_READ_BUFF);

	if (res != EXIT_SUCCESS)
		goto out;

	printf("[%c] %s (%d)\n", (line_ptr[0] == '0') ? 'x' : ' ',
	       "all debug output disabled", 0);
	printf("[%c] %s (%d)\n", (line_ptr[0] == '1') ? 'x' : ' ',
	       "messages related to routing / flooding / broadcasting", 1);
	printf("[%c] %s (%d)\n", (line_ptr[0] == '2') ? 'x' : ' ',
	       "messages related to route or hna added / changed / deleted", 2);
	printf("[%c] %s (%d)\n", (line_ptr[0] == '3') ? 'x' : ' ',
	       "all debug messages", 3);

out:
	if (errno == ENOENT)
		printf("To increase the log level you need to compile the module with debugging enabled (see the README)\n");

	return res;
}
