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
#include "sys.h"
#include "functions.h"

#define PATH_BUFF_LEN 200

static void interface_usage(void)
{
	printf("Usage: batctl interface [options] [add|del iface(s)] \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

static int print_interfaces(void)
{
	DIR *iface_base_dir;
	struct dirent *iface_dir;
	char *path_buff;
	int res;

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		printf("Error - could not allocate path buffer: out of memory ?\n");
		goto err;
	}

	iface_base_dir = opendir(SYS_IFACE_PATH);
	if (!iface_base_dir) {
		printf("Error - the directory '%s' could not be read: %s\n",
		       SYS_IFACE_PATH, strerror(errno));
		printf("Is the batman-adv module loaded and sysfs mounted ?\n");
		goto err_buff;
	}

	while ((iface_dir = readdir(iface_base_dir)) != NULL) {
		snprintf(path_buff, PATH_BUFF_LEN, SYS_MESH_IFACE_FMT, iface_dir->d_name);
		res = read_file("", path_buff, SINGLE_READ | USE_READ_BUFF | SILENCE_ERRORS);
		if (res != EXIT_SUCCESS)
			continue;

		if (line_ptr[strlen(line_ptr) - 1] == '\n')
			line_ptr[strlen(line_ptr) - 1] = '\0';

		if (strcmp(line_ptr, "status: none") == 0)
			goto free_line;

		free(line_ptr);
		line_ptr = NULL;

		snprintf(path_buff, PATH_BUFF_LEN, SYS_IFACE_STATUS_FMT, iface_dir->d_name);
		res = read_file("", path_buff, SINGLE_READ | USE_READ_BUFF | SILENCE_ERRORS);
		if (res != EXIT_SUCCESS) {
			printf("<error reading status>\n");
			continue;
		}

		printf("%s: %s", iface_dir->d_name, line_ptr);

free_line:
		free(line_ptr);
		line_ptr = NULL;
	}

	free(path_buff);
	closedir(iface_base_dir);
	return EXIT_SUCCESS;

err_buff:
	free(path_buff);
err:
	return EXIT_FAILURE;
}

int interface(int argc, char **argv)
{
	char *path_buff;
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
		return print_interfaces();

	if ((strcmp(argv[1], "add") != 0) && (strcmp(argv[1], "a") != 0) &&
	    (strcmp(argv[1], "del") != 0) && (strcmp(argv[1], "d") != 0)) {
		printf("Error - unknown argument specified: %s\n", argv[1]);
		interface_usage();
		goto err;
	}

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		printf("Error - could not allocate path buffer: out of memory ?\n");
		goto err;
	}

	for (i = 2; i < argc; i++) {
		snprintf(path_buff, PATH_BUFF_LEN, SYS_MESH_IFACE_FMT, argv[i]);

		if (argv[1][0] == 'a')
			res = write_file("", path_buff, "bat0", NULL);
		else
			res = write_file("", path_buff, "none", NULL);

		if (res != EXIT_SUCCESS)
			goto err_buff;
	}

	free(path_buff);
	return EXIT_SUCCESS;

err_buff:
	free(path_buff);
err:
	return EXIT_FAILURE;
}

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
	char space_char;
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

	while ((space_ptr = strchr_anyof(line_ptr, " \n")) != NULL) {
		space_char = *space_ptr;
		*space_ptr = '\0';
		comma_char = NULL;

		if (strncmp(line_ptr, SEARCH_ARGS_TAG, strlen(SEARCH_ARGS_TAG)) == 0) {
			cmds = space_ptr + 1;
			goto next;
		}

		if (strlen(line_ptr) == 0)
			goto next;

		if (line_ptr[strlen(line_ptr) - 1] == ',') {
			comma_char = line_ptr + strlen(line_ptr) - 1;
			*comma_char = '\0';
		}

		if (strcmp(line_ptr, argv[1]) == 0)
			goto write_file;

next:
		*space_ptr = space_char;
		if (comma_char)
			*comma_char = ',';

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
