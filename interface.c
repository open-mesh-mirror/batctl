// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2018  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
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

#include "interface.h"

#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "main.h"
#include "sys.h"
#include "functions.h"

static void interface_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] interface [parameters] [add|del iface(s)]\n");
	fprintf(stderr, "       batctl [options] interface [parameters] [create|destroy]\n");
	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -M disable automatic creation/removal of batman-adv interface\n");
	fprintf(stderr, " \t -h print this help\n");
}

static struct nla_policy link_policy[IFLA_MAX + 1] = {
	[IFLA_IFNAME] = { .type = NLA_STRING, .maxlen = IFNAMSIZ },
	[IFLA_MASTER] = { .type = NLA_U32 },
};

struct print_interfaces_rtnl_arg {
	int ifindex;
};

static int print_interfaces_rtnl_parse(struct nl_msg *msg, void *arg)
{
	struct print_interfaces_rtnl_arg *print_arg = arg;
	struct nlattr *attrs[IFLA_MAX + 1];
	char path_buff[PATH_BUFF_LEN];
	struct ifinfomsg *ifm;
	char *ifname;
	int ret;
	const char *status;
	int master;

	ifm = nlmsg_data(nlmsg_hdr(msg));
	ret = nlmsg_parse(nlmsg_hdr(msg), sizeof(*ifm), attrs, IFLA_MAX,
			  link_policy);
	if (ret < 0)
		goto err;

	if (!attrs[IFLA_IFNAME])
		goto err;

	if (!attrs[IFLA_MASTER])
		goto err;

	ifname = nla_get_string(attrs[IFLA_IFNAME]);
	master = nla_get_u32(attrs[IFLA_MASTER]);

	/* required on older kernels which don't prefilter the results */
	if (master != print_arg->ifindex)
		goto err;

	snprintf(path_buff, sizeof(path_buff), SYS_IFACE_STATUS_FMT, ifname);
	ret = read_file("", path_buff, USE_READ_BUFF | SILENCE_ERRORS, 0, 0, 0);
	if (ret != EXIT_SUCCESS)
		status = "<error reading status>\n";
	else
		status = line_ptr;

	printf("%s: %s", ifname, status);

	free(line_ptr);
	line_ptr = NULL;

err:
	return NL_OK;
}

static int print_interfaces(char *mesh_iface)
{
	struct print_interfaces_rtnl_arg print_arg;

	if (!file_exists(module_ver_path)) {
		fprintf(stderr, "Error - batman-adv module has not been loaded\n");
		return EXIT_FAILURE;
	}

	print_arg.ifindex = if_nametoindex(mesh_iface);
	if (!print_arg.ifindex)
		return EXIT_FAILURE;

	query_rtnl_link(print_arg.ifindex, print_interfaces_rtnl_parse,
			&print_arg);

	return EXIT_SUCCESS;
}

struct count_interfaces_rtnl_arg {
	int ifindex;
	unsigned int count;
};

static int count_interfaces_rtnl_parse(struct nl_msg *msg, void *arg)
{
	struct count_interfaces_rtnl_arg *count_arg = arg;
	struct nlattr *attrs[IFLA_MAX + 1];
	struct ifinfomsg *ifm;
	int ret;
	int master;

	ifm = nlmsg_data(nlmsg_hdr(msg));
	ret = nlmsg_parse(nlmsg_hdr(msg), sizeof(*ifm), attrs, IFLA_MAX,
			  link_policy);
	if (ret < 0)
		goto err;

	if (!attrs[IFLA_IFNAME])
		goto err;

	if (!attrs[IFLA_MASTER])
		goto err;

	master = nla_get_u32(attrs[IFLA_MASTER]);

	/* required on older kernels which don't prefilter the results */
	if (master != count_arg->ifindex)
		goto err;

	count_arg->count++;

err:
	return NL_OK;
}

static unsigned int count_interfaces(char *mesh_iface)
{
	struct count_interfaces_rtnl_arg count_arg;

	count_arg.count = 0;
	count_arg.ifindex = if_nametoindex(mesh_iface);
	if (!count_arg.ifindex)
		return 0;

	query_rtnl_link(count_arg.ifindex, count_interfaces_rtnl_parse,
			&count_arg);

	return count_arg.count;
}

static int create_interface(const char *mesh_iface)
{
	struct ifinfomsg rt_hdr = {
		.ifi_family = IFLA_UNSPEC,
	};
	struct nlattr *linkinfo;
	struct nl_msg *msg;
	int err = 0;
	int ret;

	msg = nlmsg_alloc_simple(RTM_NEWLINK,
				 NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK);
	if (!msg) {
		return -ENOMEM;
	}

	ret = nlmsg_append(msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_string(msg, IFLA_IFNAME, mesh_iface);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	linkinfo = nla_nest_start(msg, IFLA_LINKINFO);
	if (!linkinfo) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_string(msg, IFLA_INFO_KIND, "batadv");
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	nla_nest_end(msg, linkinfo);

	err = netlink_simple_request(msg);

err_free_msg:
	nlmsg_free(msg);

	return err;
}

static int destroy_interface(const char *mesh_iface)
{
	struct ifinfomsg rt_hdr = {
		.ifi_family = IFLA_UNSPEC,
	};
	struct nl_msg *msg;
	int err = 0;
	int ret;

	msg = nlmsg_alloc_simple(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
	if (!msg) {
		return -ENOMEM;
	}

	ret = nlmsg_append(msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_string(msg, IFLA_IFNAME, mesh_iface);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	err = netlink_simple_request(msg);

err_free_msg:
	nlmsg_free(msg);

	return err;
}

static int set_master_interface(const char *iface, unsigned int ifmaster)
{
	struct ifinfomsg rt_hdr = {
		.ifi_family = IFLA_UNSPEC,
	};
	struct nl_msg *msg;
	int err = 0;
	int ret;

	msg = nlmsg_alloc_simple(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);
	if (!msg) {
		return -ENOMEM;
	}

	ret = nlmsg_append(msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_string(msg, IFLA_IFNAME, iface);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_u32(msg, IFLA_MASTER, ifmaster);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	err = netlink_simple_request(msg);

err_free_msg:
	nlmsg_free(msg);

	return err;
}

int interface(char *mesh_iface, int argc, char **argv)
{
	int i, optchar;
	int ret;
	unsigned int ifindex;
	unsigned int ifmaster;
	const char *long_op;
	unsigned int cnt;
	int rest_argc;
	char **rest_argv;
	bool manual_mode = false;

	while ((optchar = getopt(argc, argv, "hM")) != -1) {
		switch (optchar) {
		case 'h':
			interface_usage();
			return EXIT_SUCCESS;
		case 'M':
			manual_mode = true;
			break;
		default:
			interface_usage();
			return EXIT_FAILURE;
		}
	}

	rest_argc = argc - optind;
	rest_argv = &argv[optind];

	if (rest_argc == 0)
		return print_interfaces(mesh_iface);

	check_root_or_die("batctl interface");

	if ((strcmp(rest_argv[0], "add") != 0) && (strcmp(rest_argv[0], "a") != 0) &&
	    (strcmp(rest_argv[0], "del") != 0) && (strcmp(rest_argv[0], "d") != 0) &&
	    (strcmp(rest_argv[0], "create") != 0) && (strcmp(rest_argv[0], "c") != 0) &&
	    (strcmp(rest_argv[0], "destroy") != 0) && (strcmp(rest_argv[0], "D") != 0)) {
		fprintf(stderr, "Error - unknown argument specified: %s\n", rest_argv[0]);
		interface_usage();
		goto err;
	}

	if (strcmp(rest_argv[0], "destroy") == 0)
		rest_argv[0][0] = 'D';

	switch (rest_argv[0][0]) {
	case 'a':
	case 'd':
		if (rest_argc == 1) {
			fprintf(stderr,
				"Error - missing interface name(s) after '%s'\n",
				rest_argv[0]);
			interface_usage();
			goto err;
		}
		break;
	case 'c':
	case 'D':
		if (rest_argc != 1) {
			fprintf(stderr,
				"Error - extra parameter after '%s'\n",
				rest_argv[0]);
			interface_usage();
			goto err;
		}
		break;
	default:
		break;
	}

	switch (rest_argv[0][0]) {
	case 'c':
		ret = create_interface(mesh_iface);
		if (ret < 0) {
			fprintf(stderr,
				"Error - failed to add create batman-adv interface: %s\n",
				strerror(-ret));
			goto err;
		}
		return EXIT_SUCCESS;
	case 'D':
		ret = destroy_interface(mesh_iface);
		if (ret < 0) {
			fprintf(stderr,
				"Error - failed to destroy batman-adv interface: %s\n",
				strerror(-ret));
			goto err;
		}
		return EXIT_SUCCESS;
	default:
		break;
	}

	/* get index of batman-adv interface - or try to create it */
	ifmaster = if_nametoindex(mesh_iface);
	if (!manual_mode && !ifmaster && rest_argv[0][0] == 'a') {
		ret = create_interface(mesh_iface);
		if (ret < 0) {
			fprintf(stderr,
				"Error - failed to create batman-adv interface: %s\n",
				strerror(-ret));
			goto err;
		}

		ifmaster = if_nametoindex(mesh_iface);
	}

	if (!ifmaster) {
		ret = -ENODEV;
		fprintf(stderr,
			"Error - failed to find batman-adv interface: %s\n",
			strerror(-ret));
		goto err;
	}

	/* make sure that batman-adv is loaded or was loaded by create_interface */
	if (!file_exists(module_ver_path)) {
		fprintf(stderr, "Error - batman-adv module has not been loaded\n");
		goto err;
	}

	for (i = 1; i < rest_argc; i++) {
		ifindex = if_nametoindex(rest_argv[i]);

		if (!ifindex) {
			fprintf(stderr, "Error - interface does not exist: %s\n", rest_argv[i]);
			continue;
		}

		if (rest_argv[0][0] == 'a')
			ifindex = ifmaster;
		else
			ifindex = 0;

		ret = set_master_interface(rest_argv[i], ifindex);
		if (ret < 0) {
			if (rest_argv[0][0] == 'a')
				long_op = "add";
			else
				long_op = "delete";

			fprintf(stderr, "Error - failed to %s interface %s: %s\n",
				long_op, rest_argv[i], strerror(-ret));
			goto err;
		}
	}

	/* check if there is no interface left and then destroy mesh_iface */
	if (!manual_mode && rest_argv[0][0] == 'd') {
		cnt = count_interfaces(mesh_iface);
		if (cnt == 0)
			destroy_interface(mesh_iface);
	}

	return EXIT_SUCCESS;

err:
	return EXIT_FAILURE;
}
