// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/if_ether.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "batadv_packet.h"
#include "batman_adv.h"
#include "debug.h"
#include "debugfs.h"
#include "functions.h"
#include "main.h"
#include "netlink.h"
#include "sys.h"

#define SYS_SELECTED_RA_PATH	"/sys/module/batman_adv/parameters/routing_algo"

static void ra_mode_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] routing_algo [algorithm]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, " \t -h print this help\n");
}

static const int routing_algos_mandatory[] = {
	BATADV_ATTR_ALGO_NAME,
};

static int routing_algos_callback(struct nl_msg *msg, void *arg __maybe_unused)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *ghdr;
	const char *algo_name;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ROUTING_ALGOS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, routing_algos_mandatory,
				    ARRAY_SIZE(routing_algos_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	algo_name = nla_get_string(attrs[BATADV_ATTR_ALGO_NAME]);

	printf(" * %s\n", algo_name);

	return NL_OK;
}

static int netlink_print_routing_algos(void)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int family;
	struct print_opts opts = {
		.callback = routing_algos_callback,
	};

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	genl_connect(sock);

	family = genl_ctrl_resolve(sock, BATADV_NL_NAME);
	if (family < 0) {
		last_err = -EOPNOTSUPP;
		goto err_free_sock;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		last_err = -ENOMEM;
		goto err_free_sock;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_DUMP,
		    BATADV_CMD_GET_ROUTING_ALGOS, 1);

	nl_send_auto_complete(sock, msg);

	nlmsg_free(msg);

	opts.remaining_header = strdup("Available routing algorithms:\n");

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		last_err = -ENOMEM;
		goto err_free_sock;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, netlink_print_common_cb,
		  &opts);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, netlink_stop_callback, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, netlink_print_error, NULL);

	nl_recvmsgs(sock, cb);

err_free_sock:
	nl_socket_free(sock);

	if (!last_err)
		netlink_print_remaining_header(&opts);

	return last_err;
}

static int debug_print_routing_algos(void)
{
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		fprintf(stderr, "Error - can't mount or find debugfs\n");
		return -1;
	}

	debugfs_make_path(DEBUG_BATIF_PATH_FMT, "", full_path, sizeof(full_path));
	return read_file(full_path, DEBUG_ROUTING_ALGOS, 0, 0, 0, 0);
}

static int print_routing_algos(void)
{
	int err;

	err = netlink_print_routing_algos();
	if (err == -EOPNOTSUPP)
		err = debug_print_routing_algos();
	return err;
}

static int routing_algo(struct state *state __maybe_unused, int argc, char **argv)
{
	DIR *iface_base_dir;
	struct dirent *iface_dir;
	int optchar;
	char *path_buff;
	int res = EXIT_FAILURE;
	int first_iface = 1;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			ra_mode_usage();
			return EXIT_SUCCESS;
		default:
			ra_mode_usage();
			return EXIT_FAILURE;
		}
	}

	check_root_or_die("batctl routing_algo");

	if (argc == 2) {
		res = write_file(SYS_SELECTED_RA_PATH, "", argv[1], NULL);
		goto out;
	}

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		fprintf(stderr, "Error - could not allocate path buffer: out of memory ?\n");
		goto out;
	}

	iface_base_dir = opendir(SYS_IFACE_PATH);
	if (!iface_base_dir) {
		fprintf(stderr, "Error - the directory '%s' could not be read: %s\n",
			SYS_IFACE_PATH, strerror(errno));
		fprintf(stderr, "Is the batman-adv module loaded and sysfs mounted ?\n");
		goto free_buff;
	}

	while ((iface_dir = readdir(iface_base_dir)) != NULL) {
		snprintf(path_buff, PATH_BUFF_LEN, SYS_ROUTING_ALGO_FMT, iface_dir->d_name);
		res = read_file("", path_buff, USE_READ_BUFF | SILENCE_ERRORS, 0, 0, 0);
		if (res != EXIT_SUCCESS)
			continue;

		if (line_ptr[strlen(line_ptr) - 1] == '\n')
			line_ptr[strlen(line_ptr) - 1] = '\0';

		if (first_iface) {
			first_iface = 0;
			printf("Active routing protocol configuration:\n");
		}

		printf(" * %s: %s\n", iface_dir->d_name, line_ptr);

		free(line_ptr);
		line_ptr = NULL;
	}

	closedir(iface_base_dir);
	free(path_buff);

	if (!first_iface)
		printf("\n");

	res = read_file("", SYS_SELECTED_RA_PATH, USE_READ_BUFF, 0, 0, 0);
	if (res != EXIT_SUCCESS)
		return EXIT_FAILURE;

	printf("Selected routing algorithm (used when next batX interface is created):\n");
	printf(" => %s\n", line_ptr);
	free(line_ptr);
	line_ptr = NULL;

	print_routing_algos();
	return EXIT_SUCCESS;

free_buff:
	free(path_buff);
out:
	return res;
}

COMMAND(SUBCOMMAND, routing_algo, "ra", 0, NULL,
	"[mode]            \tdisplay or modify the routing algorithm");
