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
#include <sys/types.h>
#include <dirent.h>

#include "main.h"
#include "debug.h"
#include "debugfs.h"
#include "functions.h"

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

int handle_debug_table(int argc, char **argv, char *file_path, void table_usage(void))
{
	int optchar, read_opt = USE_BAT_HOSTS;
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;

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

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		printf("Error - can't mount or find debugfs\n");
		return EXIT_FAILURE;
	}

	debugfs_make_path(DEBUG_BATIF_PATH "/", full_path, sizeof(full_path));
	return read_file(full_path, file_path, read_opt);
}

static void log_usage(void)
{
	printf("Usage: batctl [options] log \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

int log_print(int argc, char **argv)
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

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		printf("Error - can't mount or find debugfs\n");
		return EXIT_FAILURE;
	}

	debugfs_make_path(DEBUG_BATIF_PATH "/", full_path, sizeof(full_path));
	res = read_file(full_path, DEBUG_LOG, read_opt);

	if ((res != EXIT_SUCCESS) && (errno == ENOENT))
		printf("To read the debug log you need to compile the module with debugging enabled (see the README)\n");

	return res;
}
