// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2007-2019  B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <mareklindner@neomailbox.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */


#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "main.h"
#include "sys.h"
#include "debug.h"
#include "functions.h"
#include "netlink.h"

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
	char buf[32];
	size_t i;

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

			if (!cmd->usage)
				continue;

			if (strcmp(cmd->name, cmd->abbr) == 0)
				snprintf(buf, sizeof(buf), "%s", cmd->name);
			else
				snprintf(buf, sizeof(buf), "%s|%s", cmd->name,
					 cmd->abbr);

			fprintf(stderr, " \t%-27s%s\n", buf, cmd->usage);
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
	struct state state = {
		.arg_iface = mesh_dfl_iface,
		.cmd = NULL,
	};
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "+hm:v")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		case 'm':
			if (state.arg_iface != mesh_dfl_iface) {
				fprintf(stderr,
					"Error - multiple mesh interfaces specified\n");
				goto err;
			}

			state.arg_iface = argv[2];
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

	cmd = find_command(argv[0]);
	if (!cmd) {
		fprintf(stderr,
			"Error - no valid command or debug table specified: %s\n",
			argv[0]);
		goto err;
	}

	state.cmd = cmd;

	translate_mesh_iface(&state);

	if (cmd->flags & COMMAND_FLAG_MESH_IFACE &&
	    check_mesh_iface(&state) < 0) {
		fprintf(stderr,
			"Error - interface %s is not present or not a batman-adv interface\n",
			state.mesh_iface);
		exit(EXIT_FAILURE);
	}

	if (cmd->flags & COMMAND_FLAG_NETLINK) {
		ret = netlink_create(&state);
		if (ret < 0 && ret != -EOPNOTSUPP) {
			/* TODO handle -EOPNOTSUPP as error when fallbacks were
			 * removed
			 */
			fprintf(stderr,
				"Error - failed to connect to batadv\n");
			exit(EXIT_FAILURE);
		}
	}

	ret = cmd->handler(&state, argc, argv);

	if (cmd->flags & COMMAND_FLAG_NETLINK)
		netlink_destroy(&state);

	return ret;

err:
	print_usage();
	exit(EXIT_FAILURE);
}
