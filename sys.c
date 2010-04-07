/*
 * Copyright (C) 2009-2010 B.A.T.M.A.N. contributors:
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
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
	printf(" \t -w watch mode - read the log file continuously\n");
}

int log_print(int argc, char **argv)
{
	int optchar, read_opt = USE_BAT_HOSTS | LOG_MODE;
	int found_args = 1;

	while ((optchar = getopt(argc, argv, "hnw")) != -1) {
		switch (optchar) {
		case 'h':
			log_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		case 'w':
			read_opt |= CONT_READ;
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
		return read_file("", "/proc/self/fd/0", read_opt);
}

static void log_level_usage(void)
{
	printf("Usage: batctl [options] loglevel [level]\n");
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
		res = write_file(SYS_MODULE_PATH, SYS_LOG_LEVEL, argv[1], NULL);
		goto out;
	}

	res = read_file(SYS_MODULE_PATH, SYS_LOG_LEVEL, SINGLE_READ | USE_READ_BUFF);

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

void originators_usage(void)
{
	printf("Usage: batctl [options] originators \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
	printf(" \t -w watch mode - refresh the originator table continuously\n");
}

void trans_local_usage(void)
{
	printf("Usage: batctl [options] translocal \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
	printf(" \t -w watch mode - refresh the local translation table continuously\n");
}

void trans_global_usage(void)
{
	printf("Usage: batctl [options] transglobal \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
	printf(" \t -w watch mode - refresh the global translation table continuously\n");
}

int handle_sys_table(int argc, char **argv, char *file_path, void table_usage(void))
{
	int optchar, read_opt = USE_BAT_HOSTS;

	while ((optchar = getopt(argc, argv, "hnw")) != -1) {
		switch (optchar) {
		case 'h':
			table_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			break;
		case 'w':
			read_opt |= CLR_CONT_READ;
			break;
		default:
			table_usage();
			return EXIT_FAILURE;
		}
	}

	return read_file(SYS_BATIF_PATH, file_path, read_opt);
}

void aggregation_usage(void)
{
	printf("Usage: batctl [options] aggregation [0|1]\n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

void vis_mode_usage(void)
{
	printf("Usage: batctl [options] vis_mode [mode]\n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

void orig_interval_usage(void)
{
	printf("Usage: batctl [options] interval \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int handle_sys_setting(int argc, char **argv, char *file_path, void setting_usage(void))
{
	int optchar, res;
	char *space_ptr, *comma_char, *cmds = NULL;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			setting_usage();
			return EXIT_SUCCESS;
		default:
			setting_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc == 1)
		return read_file(SYS_BATIF_PATH, file_path, SINGLE_READ);

	res = read_file(SYS_BATIF_PATH, file_path, SEARCH_ARGS);
	if (res != EXIT_SUCCESS)
		return res;

	while ((space_ptr = strchr(line_ptr, ' ')) != NULL) {
		*space_ptr = '\0';

		if (strncmp(line_ptr, SEARCH_ARGS_TAG, strlen(SEARCH_ARGS_TAG)) == 0) {
			cmds = space_ptr + 1;
			goto next;
		}

		comma_char = NULL;
		if (line_ptr[strlen(line_ptr) - 1] == ',') {
			comma_char = line_ptr + strlen(line_ptr) - 1;
			*comma_char = '\0';
		}

		if (strcmp(line_ptr, argv[1]) == 0)
			goto write_file;

		*space_ptr = ' ';
		if (comma_char)
			*comma_char = ',';

next:
		line_ptr = space_ptr + 1;
	}

	if (!cmds)
		goto write_file;

	printf("Error - the supplied argument is invalid: %s\n", argv[1]);
	printf("The following values are allowed: %s", cmds);
	return EXIT_FAILURE;

write_file:
	return write_file(SYS_BATIF_PATH, file_path, argv[1], argc > 2 ? argv[2] : NULL);
}
