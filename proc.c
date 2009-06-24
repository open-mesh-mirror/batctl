/* Copyright (C) 2009 B.A.T.M.A.N. contributors:
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

void interface_usage(void)
{
	printf("Usage: batctl interface [options] \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int interface(int argc, char **argv)
{
	int i, res;

	if (argc == 1)
		return read_proc_file(PROC_INTERFACES, SINGLE_READ);

	if (strcmp(argv[1], "-h") == 0) {
		interface_usage();
		return EXIT_SUCCESS;
	}

	for (i = 1; i <= argc; i++) {
		res = write_proc_file(PROC_INTERFACES, argv[i]);

		if (res != EXIT_SUCCESS)
			return res;
	}

	return EXIT_SUCCESS;
}

void originators_usage(void)
{
	printf("Usage: batctl origs [options] \n");
	printf("options:\n");
	printf(" \t -b batch mode - read the originator table once and quit\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't replace mac addresses with bat-host names\n");
}

int originators(int argc, char **argv)
{
	int optchar, read_opt = CLR_CONT_READ + USE_BAT_HOSTS;

	while ((optchar = getopt(argc, argv, "bhn")) != -1) {
		switch (optchar) {
		case 'b':
			read_opt -= CLR_CONT_READ;
			break;
		case 'h':
			originators_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt -= USE_BAT_HOSTS;
			break;
		default:
			originators_usage();
			return EXIT_FAILURE;
		}
	}

	return read_proc_file(PROC_ORIGINATORS, read_opt);
}

void orig_interval_usage(void)
{
	printf("Usage: batctl interval [options] \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int orig_interval(int argc, char **argv)
{
	if (argc == 1)
		return read_proc_file(PROC_ORIG_INTERVAL, SINGLE_READ);

	if (strcmp(argv[1], "-h") == 0) {
		orig_interval_usage();
		return EXIT_SUCCESS;
	}

	return write_proc_file(PROC_ORIG_INTERVAL, argv[1]);
}

void log_level_usage(void)
{
	printf("Usage: batctl loglevel [options] \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int log_level(int argc, char **argv)
{
	if (argc == 1)
		return read_proc_file(PROC_LOG_LEVEL, SINGLE_READ);

	if (strcmp(argv[1], "-h") == 0) {
		log_level_usage();
		return EXIT_SUCCESS;
	}

	return write_proc_file(PROC_LOG_LEVEL, argv[1]);
}

void log_usage(void)
{
	printf("Usage: batctl log [options] \n");
	printf("options:\n");
	printf(" \t -b batch mode - read the log file once and quit\n");
	printf(" \t -h print this help\n");
}

int log_print(int argc, char **argv)
{
	int optchar, read_opt = CONT_READ;

	while ((optchar = getopt(argc, argv, "bh")) != -1) {
		switch (optchar) {
		case 'b':
			read_opt -= CONT_READ;
			break;
		case 'h':
			log_usage();
			return EXIT_SUCCESS;
		default:
			log_usage();
			return EXIT_FAILURE;
		}
	}

	return read_proc_file(PROC_LOG, read_opt);
}

