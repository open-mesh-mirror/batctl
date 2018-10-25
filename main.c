// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2007-2018  B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <mareklindner@neomailbox.ch>
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
#include <unistd.h>
#include <string.h>

#include "main.h"
#include "sys.h"
#include "debug.h"
#include "functions.h"

char mesh_dfl_iface[] = "bat0";
char module_ver_path[] = "/sys/module/batman_adv/version";

extern const struct command *__start___command[];
extern const struct command *__stop___command[];

static void print_usage(void)
{
	enum command_type type[] = {
		SUBCOMMAND,
		DEBUGTABLE,
	};
	const struct command **p;
	int opt_indent;
	char buf[32];
	size_t i;
	size_t j;

	fprintf(stderr, "Usage: batctl [options] command|debug table [parameters]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, " \t-m mesh interface or VLAN created on top of a mesh interface (default 'bat0')\n");
	fprintf(stderr, " \t-h print this help (or 'batctl <command|debug table> -h' for the parameter help)\n");
	fprintf(stderr, " \t-v print version\n");

	for (i = 0; i < sizeof(type) / sizeof(*type); i++) {
		fprintf(stderr, "\n");

		switch (type[i]) {
		case SUBCOMMAND:
			fprintf(stderr, "commands:\n");
			break;
		case DEBUGTABLE:
			fprintf(stderr, "debug tables:                                   \tdisplay the corresponding debug table\n");
			break;
		}

		for (p = __start___command; p < __stop___command; p++) {
			const struct command *cmd = *p;

			if (cmd->type != type[i])
				continue;

			if (strcmp(cmd->name, cmd->abbr) == 0)
				snprintf(buf, sizeof(buf), "%s", cmd->name);
			else
				snprintf(buf, sizeof(buf), "%s|%s", cmd->name,
					 cmd->abbr);

			fprintf(stderr, " \t%-27s%s\n", buf, cmd->usage);
		}

		if (type[i] == SUBCOMMAND) {
			for (j = 0; j < BATCTL_SETTINGS_NUM; j++) {
				fprintf(stderr, " \t%s|%s", batctl_settings[j].opt_long, batctl_settings[j].opt_short);
				opt_indent = strlen(batctl_settings[j].opt_long) + strlen(batctl_settings[j].opt_short);

				if (batctl_settings[j].params == sysfs_param_enable)
					fprintf(stderr, "%*s                display or modify %s setting\n",
						31 - opt_indent, "[0|1]", batctl_settings[j].opt_long);
				else if (batctl_settings[j].params == sysfs_param_server)
					fprintf(stderr, "%*s      display or modify %s setting\n",
						41 - opt_indent, "[client|server]", batctl_settings[j].opt_long);
				else
					fprintf(stderr, "                                display or modify %s setting\n",
						batctl_settings[j].opt_long);
			}
		}
	}
}

static void version(void)
{
	int ret;

	printf("batctl %s [batman-adv: ", SOURCE_VERSION);

	ret = read_file("", module_ver_path, USE_READ_BUFF | SILENCE_ERRORS, 0, 0, 0);
	if ((line_ptr) && (line_ptr[strlen(line_ptr) - 1] == '\n'))
		line_ptr[strlen(line_ptr) - 1] = '\0';

	if (ret == EXIT_SUCCESS)
		printf("%s]\n", line_ptr);
	else
		printf("module not loaded]\n");

	free(line_ptr);
	exit(EXIT_SUCCESS);
}

static const struct command *find_command(const char *name)
{
	const struct command **p;

	for (p = __start___command; p < __stop___command; p++) {
		const struct command *cmd = *p;

		if (strcmp(cmd->name, name) == 0)
			return cmd;

		if (strcmp(cmd->abbr, name) == 0)
			return cmd;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	const struct command *cmd;
	int i, ret = EXIT_FAILURE;
	struct state state = {
		.mesh_iface = mesh_dfl_iface,
		.cmd = NULL,
	};
	int opt;

	while ((opt = getopt(argc, argv, "+hm:v")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		case 'm':
			if (state.mesh_iface != mesh_dfl_iface) {
				fprintf(stderr,
					"Error - multiple mesh interfaces specified\n");
				goto err;
			}

			state.mesh_iface = argv[2];
			break;
		case 'v':
			version();
			break;
		default:
			goto err;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error - no command specified\n");
		goto err;
	}

	argv += optind;
	argc -= optind;
	optind = 0;

	if ((cmd = find_command(argv[0]))) {
		state.cmd = cmd;

		if (cmd->flags & COMMAND_FLAG_MESH_IFACE &&
		    check_mesh_iface(state.mesh_iface) < 0) {
			fprintf(stderr,
				"Error - interface %s is not present or not a batman-adv interface\n",
				state.mesh_iface);
			exit(EXIT_FAILURE);
		}

		ret = cmd->handler(&state, argc, argv);
	} else {
		if (check_mesh_iface(state.mesh_iface) < 0) {
			fprintf(stderr,
				"Error - interface %s is not present or not a batman-adv interface\n",
				state.mesh_iface);
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < BATCTL_SETTINGS_NUM; i++) {
			if ((strcmp(argv[0], batctl_settings[i].opt_long) != 0) &&
			    (strcmp(argv[0], batctl_settings[i].opt_short) != 0))
				continue;

			ret = handle_sys_setting(state.mesh_iface, i, argc, argv);
			goto out;
		}

		fprintf(stderr,
			"Error - no valid command or debug table specified: %s\n",
			argv[0]);
		print_usage();
	}

out:
	return ret;

err:
	print_usage();
	exit(EXIT_FAILURE);
}
