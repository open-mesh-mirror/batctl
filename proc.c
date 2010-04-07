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
		return read_file(PROC_ROOT_PATH, PROC_INTERFACES, SINGLE_READ);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "none") == 0)
			res = write_file(PROC_ROOT_PATH, PROC_INTERFACES, "", NULL);
		else
			res = write_file(PROC_ROOT_PATH, PROC_INTERFACES, argv[i], NULL);

		if (res != EXIT_SUCCESS)
			return res;
	}

	return EXIT_SUCCESS;
}

int handle_table(int argc, char **argv, char *file_path, void table_usage(void))
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

	return read_file(PROC_ROOT_PATH, file_path, read_opt);
}

int handle_proc_setting(int argc, char **argv, char *file_path, void setting_usage(void))
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
		return read_file(PROC_ROOT_PATH, file_path, SINGLE_READ);

	return write_file(PROC_ROOT_PATH, file_path, argv[1], NULL);
}
