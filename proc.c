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



#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "main.h"
#include "proc.h"
#include "functions.h"

static void interface_usage(void)
{
	printf("Usage: batctl interface [options] [none|interface] \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int interface(int argc, char **argv)
{
	int i, res, optchar;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			interface_usage();
			return EXIT_SUCCESS;
		default:
			interface_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc == 1)
		return read_proc_file(PROC_INTERFACES, SINGLE_READ);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "none") == 0)
			res = write_proc_file(PROC_INTERFACES, "");
		else
			res = write_proc_file(PROC_INTERFACES, argv[i]);

		if (res != EXIT_SUCCESS)
			return res;
	}

	return EXIT_SUCCESS;
}

static void log_usage(void)
{
	printf("Usage: batctl [options] log \n");
	printf("options:\n");
	printf(" \t -b batch mode - read the log file once and quit\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

int log_print(int argc, char **argv)
{
	int optchar, read_opt = CONT_READ | USE_BAT_HOSTS | LOG_MODE;

	while ((optchar = getopt(argc, argv, "bhn")) != -1) {
		switch (optchar) {
		case 'b':
			read_opt &= ~CONT_READ;
			break;
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

	return read_proc_file(PROC_LOG, read_opt);
}

void originators_usage(void)
{
	printf("Usage: batctl [options] originators \n");
	printf("options:\n");
	printf(" \t -b batch mode - read the originator table once and quit\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

void trans_local_usage(void)
{
	printf("Usage: batctl [options] translocal \n");
	printf("options:\n");
	printf(" \t -b batch mode - read the local translation table once and quit\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

void trans_global_usage(void)
{
	printf("Usage: batctl [options] transglobal \n");
	printf("options:\n");
	printf(" \t -b batch mode - read the global translation table once and quit\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

void orig_interval_usage(void)
{
	printf("Usage: batctl [options] interval \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

void log_level_usage(void)
{
	printf("Usage: batctl [options] loglevel \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

void vis_format_usage(void)
{
	printf("Usage: batctl [options] visformat \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

void aggregation_usage(void)
{
	printf("Usage: batctl [options] aggregation \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int handle_table(int argc, char **argv, char *file_path, void table_usage(void))
{
	int optchar, read_opt = CLR_CONT_READ | USE_BAT_HOSTS;

	while ((optchar = getopt(argc, argv, "bhn")) != -1) {
		switch (optchar) {
		case 'b':
			read_opt &= ~CLR_CONT_READ;
			break;
		case 'h':
			table_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			break;
		default:
			table_usage();
			return EXIT_FAILURE;
		}
	}

	return read_proc_file(file_path, read_opt);
}

int handle_setting(int argc, char **argv, char *file_path, void setting_usage(void))
{
	int optchar;

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
		return read_proc_file(file_path, SINGLE_READ);

	return write_proc_file(file_path, argv[1]);
}
