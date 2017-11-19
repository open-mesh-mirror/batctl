// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2017  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>, Andrew Lunn <andrew@lunn.ch>
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

#include "netlink.h"
#include "main.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bat-hosts.h"
#include "batman_adv.h"
#include "netlink.h"
#include "functions.h"
#include "main.h"
#include "packet.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#ifndef container_of
#define container_of(ptr, type, member) __extension__ ({ \
	const __typeof__(((type *)0)->member) *__pmember = (ptr); \
	(type *)((char *)__pmember - offsetof(type, member)); })
#endif

struct print_opts {
	int read_opt;
	float orig_timeout;
	float watch_interval;
	nl_recvmsg_msg_cb_t callback;
	char *remaining_header;
	const char *static_header;
	uint8_t nl_cmd;
};

struct nlquery_opts {
	int err;
};

struct nla_policy batadv_netlink_policy[NUM_BATADV_ATTR] = {
	[BATADV_ATTR_VERSION]		= { .type = NLA_STRING },
	[BATADV_ATTR_ALGO_NAME]		= { .type = NLA_STRING },
	[BATADV_ATTR_MESH_IFINDEX]	= { .type = NLA_U32 },
	[BATADV_ATTR_MESH_IFNAME]	= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ },
	[BATADV_ATTR_MESH_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_HARD_IFINDEX]	= { .type = NLA_U32 },
	[BATADV_ATTR_HARD_IFNAME]	= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ },
	[BATADV_ATTR_HARD_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_ORIG_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TPMETER_RESULT]	= { .type = NLA_U8 },
	[BATADV_ATTR_TPMETER_TEST_TIME]	= { .type = NLA_U32 },
	[BATADV_ATTR_TPMETER_BYTES]	= { .type = NLA_U64 },
	[BATADV_ATTR_TPMETER_COOKIE]	= { .type = NLA_U32 },
	[BATADV_ATTR_PAD]		= { .type = NLA_UNSPEC },
	[BATADV_ATTR_ACTIVE]		= { .type = NLA_FLAG },
	[BATADV_ATTR_TT_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TT_TTVN]		= { .type = NLA_U8 },
	[BATADV_ATTR_TT_LAST_TTVN]	= { .type = NLA_U8 },
	[BATADV_ATTR_TT_CRC32]		= { .type = NLA_U32 },
	[BATADV_ATTR_TT_VID]		= { .type = NLA_U16 },
	[BATADV_ATTR_TT_FLAGS]		= { .type = NLA_U32 },
	[BATADV_ATTR_FLAG_BEST]		= { .type = NLA_FLAG },
	[BATADV_ATTR_LAST_SEEN_MSECS]	= { .type = NLA_U32 },
	[BATADV_ATTR_NEIGH_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TQ]		= { .type = NLA_U8 },
	[BATADV_ATTR_THROUGHPUT]	= { .type = NLA_U32 },
	[BATADV_ATTR_BANDWIDTH_UP]	= { .type = NLA_U32 },
	[BATADV_ATTR_BANDWIDTH_DOWN]	= { .type = NLA_U32 },
	[BATADV_ATTR_ROUTER]		= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_OWN]		= { .type = NLA_FLAG },
	[BATADV_ATTR_BLA_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_VID]		= { .type = NLA_U16 },
	[BATADV_ATTR_BLA_BACKBONE]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_CRC]		= { .type = NLA_U16 },
};

static int last_err;
static char algo_name_buf[256] = "";

static int missing_mandatory_attrs(struct nlattr *attrs[],
				   const int mandatory[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		if (!attrs[mandatory[i]])
			return -EINVAL;

	return 0;
}

static int print_error(struct sockaddr_nl *nla __maybe_unused,
		       struct nlmsgerr *nlerr,
		       void *arg __maybe_unused)
{
	if (nlerr->error != -EOPNOTSUPP)
		fprintf(stderr, "Error received: %s\n",
			strerror(-nlerr->error));

	last_err = nlerr->error;

	return NL_STOP;
}

static int stop_callback(struct nl_msg *msg, void *arg __maybe_unused)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	int *error = nlmsg_data(nlh);

	if (*error)
		fprintf(stderr, "Error received: %s\n", strerror(-*error));

	return NL_STOP;
}

static const int info_mandatory[] = {
	BATADV_ATTR_MESH_IFINDEX,
	BATADV_ATTR_MESH_IFNAME,
};

static const int info_hard_mandatory[] = {
	BATADV_ATTR_VERSION,
	BATADV_ATTR_ALGO_NAME,
	BATADV_ATTR_HARD_IFNAME,
	BATADV_ATTR_HARD_ADDRESS,
};

static int info_callback(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct print_opts *opts = arg;
	const uint8_t *primary_mac;
	struct genlmsghdr *ghdr;
	const uint8_t *mesh_mac;
	const char *primary_if;
	const char *mesh_name;
	const char *version;
	char *extra_info = NULL;
	uint8_t ttvn = 0;
	uint16_t bla_group_id = 0;
	const char *algo_name;
	const char *extra_header;
	int ret;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_MESH_INFO)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, info_mandatory,
				    ARRAY_SIZE(info_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	mesh_name = nla_get_string(attrs[BATADV_ATTR_MESH_IFNAME]);
	mesh_mac = nla_data(attrs[BATADV_ATTR_MESH_ADDRESS]);

	if (attrs[BATADV_ATTR_HARD_IFNAME]) {
		if (missing_mandatory_attrs(attrs, info_hard_mandatory,
					    ARRAY_SIZE(info_hard_mandatory))) {
			fputs("Missing attributes from kernel\n",
			      stderr);
			exit(1);
		}

		version = nla_get_string(attrs[BATADV_ATTR_VERSION]);
		algo_name = nla_get_string(attrs[BATADV_ATTR_ALGO_NAME]);
		primary_if = nla_get_string(attrs[BATADV_ATTR_HARD_IFNAME]);
		primary_mac = nla_data(attrs[BATADV_ATTR_HARD_ADDRESS]);

		snprintf(algo_name_buf, sizeof(algo_name_buf), "%s", algo_name);

		if (attrs[BATADV_ATTR_TT_TTVN])
			ttvn = nla_get_u8(attrs[BATADV_ATTR_TT_TTVN]);

		if (attrs[BATADV_ATTR_BLA_CRC])
			bla_group_id = nla_get_u16(attrs[BATADV_ATTR_BLA_CRC]);

		switch (opts->nl_cmd) {
		case BATADV_CMD_GET_TRANSTABLE_LOCAL:
			ret = asprintf(&extra_info, ", TTVN: %u", ttvn);
			if (ret < 0)
				extra_info = NULL;
			break;
		case BATADV_CMD_GET_BLA_BACKBONE:
		case BATADV_CMD_GET_BLA_CLAIM:
			ret = asprintf(&extra_info, ", group id: 0x%04x",
				       bla_group_id);
			if (ret < 0)
				extra_info = NULL;
			break;
		default:
			extra_info = strdup("");
			break;
		}

		if (opts->static_header)
			extra_header = opts->static_header;
		else
			extra_header = "";

		ret = asprintf(&opts->remaining_header,
			       "[B.A.T.M.A.N. adv %s, MainIF/MAC: %s/%02x:%02x:%02x:%02x:%02x:%02x (%s/%02x:%02x:%02x:%02x:%02x:%02x %s)%s]\n%s",
			       version, primary_if,
			       primary_mac[0], primary_mac[1], primary_mac[2],
			       primary_mac[3], primary_mac[4], primary_mac[5],
			       mesh_name,
			       mesh_mac[0], mesh_mac[1], mesh_mac[2],
			       mesh_mac[3], mesh_mac[4], mesh_mac[5],
			       algo_name, extra_info, extra_header);
		if (ret < 0)
			opts->remaining_header = NULL;

		if (extra_info)
			free(extra_info);
	} else {
		ret = asprintf(&opts->remaining_header,
			       "BATMAN mesh %s disabled\n", mesh_name);
		if (ret < 0)
			opts->remaining_header = NULL;
	}

	return NL_STOP;
}

static char *netlink_get_info(int ifindex, uint8_t nl_cmd, const char *header)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int family;
	struct print_opts opts = {
		.read_opt = 0,
		.nl_cmd = nl_cmd,
		.remaining_header = NULL,
		.static_header = header,
	};

	sock = nl_socket_alloc();
	if (!sock)
		return NULL;

	genl_connect(sock);

	family = genl_ctrl_resolve(sock, BATADV_NL_NAME);
	if (family < 0) {
		nl_socket_free(sock);
		return NULL;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		nl_socket_free(sock);
		return NULL;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 0,
		    BATADV_CMD_GET_MESH_INFO, 1);

	nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, ifindex);

	nl_send_auto_complete(sock, msg);

	nlmsg_free(msg);

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto err_free_sock;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, info_callback, &opts);
	nl_cb_err(cb, NL_CB_CUSTOM, print_error, NULL);

	nl_recvmsgs(sock, cb);

err_free_sock:
	nl_socket_free(sock);

	return opts.remaining_header;
}

static void netlink_print_remaining_header(struct print_opts *opts)
{
	if (!opts->remaining_header)
		return;

	fputs(opts->remaining_header, stdout);
	free(opts->remaining_header);
	opts->remaining_header = NULL;
}

static int netlink_print_common_cb(struct nl_msg *msg, void *arg)
{
	struct print_opts *opts = arg;

	netlink_print_remaining_header(opts);

	return opts->callback(msg, arg);
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

int netlink_print_routing_algos(void)
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
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, stop_callback, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, print_error, NULL);

	nl_recvmsgs(sock, cb);

err_free_sock:
	nl_socket_free(sock);

	if (!last_err)
		netlink_print_remaining_header(&opts);

	return last_err;
}

static const int originators_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static int originators_callback(struct nl_msg *msg, void *arg)
{
	unsigned throughput_mbits, throughput_kbits;
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	int last_seen_msecs, last_seen_secs;
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	struct genlmsghdr *ghdr;
	char ifname[IF_NAMESIZE];
	float last_seen;
	uint8_t *neigh;
	uint8_t *orig;
	char c = ' ';
	uint8_t tq;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, originators_mandatory,
				       ARRAY_SIZE(originators_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	neigh = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);

	if (!if_indextoname(nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]),
			    ifname))
		ifname[0] = '\0';

	if (attrs[BATADV_ATTR_FLAG_BEST])
		c = '*';

	last_seen_msecs = nla_get_u32(attrs[BATADV_ATTR_LAST_SEEN_MSECS]);
	last_seen = (float)last_seen_msecs / 1000.0;
	last_seen_secs = last_seen_msecs / 1000;
	last_seen_msecs = last_seen_msecs % 1000;

	/* skip timed out originators */
	if (opts->read_opt & NO_OLD_ORIGS)
		if (last_seen > opts->orig_timeout)
			return NL_OK;

	if (attrs[BATADV_ATTR_THROUGHPUT]) {
		throughput_kbits = nla_get_u32(attrs[BATADV_ATTR_THROUGHPUT]);
		throughput_mbits = throughput_kbits / 1000;
		throughput_kbits = throughput_kbits % 1000;

		if (!(opts->read_opt & USE_BAT_HOSTS)) {
			printf(" %c %02x:%02x:%02x:%02x:%02x:%02x %4i.%03is (%9u.%1u) %02x:%02x:%02x:%02x:%02x:%02x [%10s]\n",
			       c,
			       orig[0], orig[1], orig[2],
			       orig[3], orig[4], orig[5],
			       last_seen_secs, last_seen_msecs,
			       throughput_mbits, throughput_kbits / 100,
			       neigh[0], neigh[1], neigh[2],
			       neigh[3], neigh[4], neigh[5],
			       ifname);
		} else {
			bat_host = bat_hosts_find_by_mac((char *)orig);
			if (bat_host)
				printf(" %c %17s ", c, bat_host->name);
			else
				printf(" %c %02x:%02x:%02x:%02x:%02x:%02x ",
				       c,
				       orig[0], orig[1], orig[2],
				       orig[3], orig[4], orig[5]);
			printf("%4i.%03is (%9u.%1u) ",
			       last_seen_secs, last_seen_msecs,
			       throughput_mbits, throughput_kbits / 100);
			bat_host = bat_hosts_find_by_mac((char *)neigh);
			if (bat_host)
				printf(" %c %17s ", c, bat_host->name);
			else
				printf(" %02x:%02x:%02x:%02x:%02x:%02x ",
				       neigh[0], neigh[1], neigh[2],
				       neigh[3], neigh[4], neigh[5]);
			printf("[%10s]\n", ifname);
		}
	}
	if (attrs[BATADV_ATTR_TQ]) {
		tq = nla_get_u8(attrs[BATADV_ATTR_TQ]);

		if (!(opts->read_opt & USE_BAT_HOSTS)) {
			printf(" %c %02x:%02x:%02x:%02x:%02x:%02x %4i.%03is   (%3i) %02x:%02x:%02x:%02x:%02x:%02x [%10s]\n",
			       c,
			       orig[0], orig[1], orig[2],
			       orig[3], orig[4], orig[5],
			       last_seen_secs, last_seen_msecs, tq,
			       neigh[0], neigh[1], neigh[2],
			       neigh[3], neigh[4], neigh[5],
			       ifname);
		} else {
			bat_host = bat_hosts_find_by_mac((char *)orig);
			if (bat_host)
				printf(" %c %17s ", c, bat_host->name);
			else
				printf(" %c %02x:%02x:%02x:%02x:%02x:%02x ",
				       c,
				       orig[0], orig[1], orig[2],
				       orig[3], orig[4], orig[5]);
			printf("%4i.%03is   (%3i) ",
			       last_seen_secs, last_seen_msecs, tq);
			bat_host = bat_hosts_find_by_mac((char *)neigh);
			if (bat_host)
				printf("%17s ", bat_host->name);
			else
				printf("%02x:%02x:%02x:%02x:%02x:%02x ",
				       neigh[0], neigh[1], neigh[2],
				       neigh[3], neigh[4], neigh[5]);
			printf("[%10s]\n", ifname);
		}
	}

	return NL_OK;
}

static const int neighbors_mandatory[] = {
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static int neighbors_callback(struct nl_msg *msg, void *arg)
{
	unsigned throughput_mbits, throughput_kbits;
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	int last_seen_msecs, last_seen_secs;
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	char ifname[IF_NAMESIZE];
	struct genlmsghdr *ghdr;
	uint8_t *neigh;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_NEIGHBORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, neighbors_mandatory,
				    ARRAY_SIZE(neighbors_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	neigh = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);
	bat_host = bat_hosts_find_by_mac((char *)neigh);

	if (!if_indextoname(nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]),
			    ifname))
		ifname[0] = '\0';

	last_seen_msecs = nla_get_u32(attrs[BATADV_ATTR_LAST_SEEN_MSECS]);
	last_seen_secs = last_seen_msecs / 1000;
	last_seen_msecs = last_seen_msecs % 1000;

	if (attrs[BATADV_ATTR_THROUGHPUT]) {
		throughput_kbits = nla_get_u32(attrs[BATADV_ATTR_THROUGHPUT]);
		throughput_mbits = throughput_kbits / 1000;
		throughput_kbits = throughput_kbits % 1000;

		if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
			printf("%02x:%02x:%02x:%02x:%02x:%02x ",
			       neigh[0], neigh[1], neigh[2],
			       neigh[3], neigh[4], neigh[5]);
		else
			printf("%17s ", bat_host->name);

		printf("%4i.%03is (%9u.%1u) [%10s]\n",
		       last_seen_secs, last_seen_msecs,
		       throughput_mbits, throughput_kbits / 100,
		       ifname);
	} else {
		printf("   %10s	  ", ifname);

		if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
			printf("%02x:%02x:%02x:%02x:%02x:%02x ",
			       neigh[0], neigh[1], neigh[2],
			       neigh[3], neigh[4], neigh[5]);
		else
			printf("%17s ", bat_host->name);

		printf("%4i.%03is\n", last_seen_secs, last_seen_msecs);
	}

	return NL_OK;
}

static const int transglobal_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_TT_VID,
	BATADV_ATTR_TT_TTVN,
	BATADV_ATTR_TT_LAST_TTVN,
	BATADV_ATTR_TT_CRC32,
	BATADV_ATTR_TT_FLAGS,
};

static int transglobal_callback(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	struct genlmsghdr *ghdr;
	char c, r, w, i, t;
	uint8_t last_ttvn;
	uint32_t crc32;
	uint32_t flags;
	uint8_t *addr;
	uint8_t *orig;
	uint8_t ttvn;
	int16_t vid;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_GLOBAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, transglobal_mandatory,
				    ARRAY_SIZE(transglobal_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	vid = nla_get_u16(attrs[BATADV_ATTR_TT_VID]);
	ttvn = nla_get_u8(attrs[BATADV_ATTR_TT_TTVN]);
	last_ttvn = nla_get_u8(attrs[BATADV_ATTR_TT_LAST_TTVN]);
	crc32 = nla_get_u32(attrs[BATADV_ATTR_TT_CRC32]);
	flags = nla_get_u32(attrs[BATADV_ATTR_TT_FLAGS]);

	if (opts->read_opt & MULTICAST_ONLY && !(addr[0] & 0x01))
		return NL_OK;

	if (opts->read_opt & UNICAST_ONLY && (addr[0] & 0x01))
		return NL_OK;

	c = ' ', r = '.', w = '.', i = '.', t = '.';
	if (attrs[BATADV_ATTR_FLAG_BEST])
		c = '*';
	if (flags & BATADV_TT_CLIENT_ROAM)
		r = 'R';
	if (flags & BATADV_TT_CLIENT_WIFI)
		w = 'W';
	if (flags & BATADV_TT_CLIENT_ISOLA)
		i = 'I';
	if (flags & BATADV_TT_CLIENT_TEMP)
		t = 'T';

	printf(" %c ", c);

	bat_host = bat_hosts_find_by_mac((char *)addr);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       addr[0], addr[1], addr[2],
		       addr[3], addr[4], addr[5]);
	else
		printf("%17s ", bat_host->name);

	printf("%4i [%c%c%c%c] (%3u) ",
	       BATADV_PRINT_VID(vid), r, w, i, t, ttvn);

	bat_host = bat_hosts_find_by_mac((char *)orig);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       orig[0], orig[1], orig[2],
		       orig[3], orig[4], orig[5]);
	else
		printf("%17s ", bat_host->name);

	printf("(%3u) (0x%.8x)\n",
	       last_ttvn, crc32);

	return NL_OK;
}

static const int translocal_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_TT_VID,
	BATADV_ATTR_TT_CRC32,
	BATADV_ATTR_TT_FLAGS,
};

static int translocal_callback(struct nl_msg *msg, void *arg)
{
	int last_seen_msecs = 0, last_seen_secs = 0;
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	struct genlmsghdr *ghdr;
	char r, p, n, x, w, i;
	uint8_t *addr;
	int16_t vid;
	uint32_t crc32;
	uint32_t flags;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_LOCAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, translocal_mandatory,
				    ARRAY_SIZE(translocal_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	vid = nla_get_u16(attrs[BATADV_ATTR_TT_VID]);
	crc32 = nla_get_u32(attrs[BATADV_ATTR_TT_CRC32]);
	flags = nla_get_u32(attrs[BATADV_ATTR_TT_FLAGS]);
	last_seen_msecs = 0, last_seen_secs = 0;

	if (opts->read_opt & MULTICAST_ONLY && !(addr[0] & 0x01))
		return NL_OK;

	if (opts->read_opt & UNICAST_ONLY && (addr[0] & 0x01))
		return NL_OK;

	r = '.', p = '.', n = '.', x = '.', w = '.', i = '.';
	if (flags & BATADV_TT_CLIENT_ROAM)
		r = 'R';
	if (flags & BATADV_TT_CLIENT_NEW)
		n = 'N';
	if (flags & BATADV_TT_CLIENT_PENDING)
		x = 'X';
	if (flags & BATADV_TT_CLIENT_WIFI)
		w = 'W';
	if (flags & BATADV_TT_CLIENT_ISOLA)
		i = 'I';

	if (flags & BATADV_TT_CLIENT_NOPURGE)  {
		p = 'P';
	} else {
		if (!attrs[BATADV_ATTR_LAST_SEEN_MSECS]) {
			fputs("Received invalid data from kernel.\n", stderr);
			exit(1);
		}

		last_seen_msecs = nla_get_u32(
			attrs[BATADV_ATTR_LAST_SEEN_MSECS]);
		last_seen_secs = last_seen_msecs / 1000;
		last_seen_msecs = last_seen_msecs % 1000;
	}

	bat_host = bat_hosts_find_by_mac((char *)addr);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       addr[0], addr[1], addr[2],
		       addr[3], addr[4], addr[5]);
	else
		printf("%17s ", bat_host->name);

	printf("%4i [%c%c%c%c%c%c] %3u.%03u   (0x%.8x)\n",
	       BATADV_PRINT_VID(vid), r, p, n, x, w, i,
	       last_seen_secs, last_seen_msecs,
	       crc32);

	return NL_OK;
}

static const int gateways_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_ROUTER,
	BATADV_ATTR_HARD_IFNAME,
	BATADV_ATTR_BANDWIDTH_DOWN,
	BATADV_ATTR_BANDWIDTH_UP,
};

static int gateways_callback(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	struct genlmsghdr *ghdr;
	const char *primary_if;
	uint32_t bandwidth_down;
	uint32_t bandwidth_up;
	uint32_t throughput;
	uint8_t *router;
	uint8_t *orig;
	char c = ' ';
	uint8_t tq;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_GATEWAYS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, gateways_mandatory,
				    ARRAY_SIZE(gateways_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	if (attrs[BATADV_ATTR_FLAG_BEST])
		c = '*';

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	router = nla_data(attrs[BATADV_ATTR_ROUTER]);
	primary_if = nla_get_string(attrs[BATADV_ATTR_HARD_IFNAME]);
	bandwidth_down = nla_get_u32(attrs[BATADV_ATTR_BANDWIDTH_DOWN]);
	bandwidth_up = nla_get_u32(attrs[BATADV_ATTR_BANDWIDTH_UP]);

	printf("%c ", c);

	bat_host = bat_hosts_find_by_mac((char *)orig);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       orig[0], orig[1], orig[2],
		       orig[3], orig[4], orig[5]);
	else
		printf("%17s ", bat_host->name);

	if (attrs[BATADV_ATTR_THROUGHPUT]) {
		throughput = nla_get_u32(attrs[BATADV_ATTR_THROUGHPUT]);
		printf("(%9u.%1u) ", throughput / 10, throughput % 10);
	} else if (attrs[BATADV_ATTR_TQ]) {
		tq = nla_get_u8(attrs[BATADV_ATTR_TQ]);
		printf("(%3i) ", tq);
	}

	bat_host = bat_hosts_find_by_mac((char *)router);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       router[0], router[1], router[2],
		       router[3], router[4], router[5]);
	else
		printf("%17s ", bat_host->name);

	printf("[%10s]: %u.%u/%u.%u MBit\n",
	       primary_if, bandwidth_down / 10, bandwidth_down % 10,
	       bandwidth_up / 10, bandwidth_up % 10);

	return NL_OK;
}

static const int bla_claim_mandatory[] = {
	BATADV_ATTR_BLA_ADDRESS,
	BATADV_ATTR_BLA_VID,
	BATADV_ATTR_BLA_BACKBONE,
	BATADV_ATTR_BLA_CRC,
};

static int bla_claim_callback(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	struct genlmsghdr *ghdr;
	uint16_t backbone_crc;
	uint8_t *backbone;
	uint8_t *client;
	uint16_t vid;
	char c = ' ';

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_BLA_CLAIM)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, bla_claim_mandatory,
				       ARRAY_SIZE(bla_claim_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	if (attrs[BATADV_ATTR_BLA_OWN])
		c = '*';

	client = nla_data(attrs[BATADV_ATTR_BLA_ADDRESS]);
	vid = nla_get_u16(attrs[BATADV_ATTR_BLA_VID]);
	backbone = nla_data(attrs[BATADV_ATTR_BLA_BACKBONE]);
	backbone_crc = nla_get_u16(attrs[BATADV_ATTR_BLA_CRC]);

	bat_host = bat_hosts_find_by_mac((char *)client);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       client[0], client[1], client[2],
		       client[3], client[4], client[5]);
	else
		printf("%17s ", bat_host->name);

	printf("on %5d by ", BATADV_PRINT_VID(vid));

	bat_host = bat_hosts_find_by_mac((char *)backbone);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       backbone[0], backbone[1], backbone[2],
		       backbone[3], backbone[4], backbone[5]);
	else
		printf("%17s ", bat_host->name);

	printf("[%c] (0x%04x)\n", c, backbone_crc);

	return NL_OK;
}

static const int bla_backbone_mandatory[] = {
	BATADV_ATTR_BLA_VID,
	BATADV_ATTR_BLA_BACKBONE,
	BATADV_ATTR_BLA_CRC,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static int bla_backbone_callback(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	int last_seen_msecs, last_seen_secs;
	struct print_opts *opts = arg;
	struct bat_host *bat_host;
	struct genlmsghdr *ghdr;
	uint16_t backbone_crc;
	uint8_t *backbone;
	uint16_t vid;

	if (!genlmsg_valid_hdr(nlh, 0)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_BLA_BACKBONE)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		exit(1);
	}

	if (missing_mandatory_attrs(attrs, bla_backbone_mandatory,
				       ARRAY_SIZE(bla_backbone_mandatory))) {
		fputs("Missing attributes from kernel\n", stderr);
		exit(1);
	}

	/* don't show own backbones */
	if (attrs[BATADV_ATTR_BLA_OWN])
		return NL_OK;

	vid = nla_get_u16(attrs[BATADV_ATTR_BLA_VID]);
	backbone = nla_data(attrs[BATADV_ATTR_BLA_BACKBONE]);
	backbone_crc = nla_get_u16(attrs[BATADV_ATTR_BLA_CRC]);

	last_seen_msecs = nla_get_u32(attrs[BATADV_ATTR_LAST_SEEN_MSECS]);
	last_seen_secs = last_seen_msecs / 1000;
	last_seen_msecs = last_seen_msecs % 1000;

	bat_host = bat_hosts_find_by_mac((char *)backbone);
	if (!(opts->read_opt & USE_BAT_HOSTS) || !bat_host)
		printf("%02x:%02x:%02x:%02x:%02x:%02x ",
		       backbone[0], backbone[1], backbone[2],
		       backbone[3], backbone[4], backbone[5]);
	else
		printf("%17s ", bat_host->name);

	printf("on %5d %4i.%03is (0x%04x)\n",
	       BATADV_PRINT_VID(vid), last_seen_secs, last_seen_msecs,
	       backbone_crc);

	return NL_OK;
}

static int netlink_print_common(char *mesh_iface, char *orig_iface,
				int read_opt, float orig_timeout,
				float watch_interval, const char *header,
				uint8_t nl_cmd, nl_recvmsg_msg_cb_t callback)
{
	struct print_opts opts = {
		.read_opt = read_opt,
		.orig_timeout = orig_timeout,
		.watch_interval = watch_interval,
		.remaining_header = NULL,
		.callback = callback,
	};
	int hardifindex = 0;
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int ifindex;
	int family;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	genl_connect(sock);

	family = genl_ctrl_resolve(sock, BATADV_NL_NAME);
	if (family < 0) {
		last_err = -EOPNOTSUPP;
		goto err_free_sock;
	}

	ifindex = if_nametoindex(mesh_iface);
	if (!ifindex) {
		fprintf(stderr, "Interface %s is unknown\n", mesh_iface);
		last_err = -ENODEV;
		goto err_free_sock;
	}

	if (orig_iface) {
		hardifindex = if_nametoindex(orig_iface);
		if (!hardifindex) {
			fprintf(stderr, "Interface %s is unknown\n",
				orig_iface);
			last_err = -ENODEV;
			goto err_free_sock;
		}
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		last_err = -ENOMEM;
		goto err_free_sock;
	}

	bat_hosts_init(read_opt);

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, netlink_print_common_cb, &opts);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, stop_callback, NULL);
	nl_cb_err(cb, NL_CB_CUSTOM, print_error, NULL);

	do {
		if (read_opt & CLR_CONT_READ)
			/* clear screen, set cursor back to 0,0 */
			printf("\033[2J\033[0;0f");

		if (!(read_opt & SKIP_HEADER))
			opts.remaining_header = netlink_get_info(ifindex,
								 nl_cmd,
								 header);

		msg = nlmsg_alloc();
		if (!msg)
			continue;

		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0,
			    NLM_F_DUMP, nl_cmd, 1);

		nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, ifindex);
		if (hardifindex)
			nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
				    hardifindex);

		nl_send_auto_complete(sock, msg);

		nlmsg_free(msg);

		last_err = 0;
		nl_recvmsgs(sock, cb);

		/* the header should still be printed when no entry was received */
		if (!last_err)
			netlink_print_remaining_header(&opts);

		if (!last_err && read_opt & (CONT_READ|CLR_CONT_READ))
			usleep(1000000 * watch_interval);

	} while (!last_err && read_opt & (CONT_READ|CLR_CONT_READ));

	bat_hosts_free();

err_free_sock:
	nl_socket_free(sock);

	return last_err;
}

int netlink_print_originators(char *mesh_iface, char *orig_iface,
			      int read_opts, float orig_timeout,
			      float watch_interval)
{
	char *header = NULL;
	char *info_header;
	int ifindex;

	ifindex = if_nametoindex(mesh_iface);
	if (!ifindex) {
		fprintf(stderr, "Interface %s is unknown\n", mesh_iface);
		return -ENODEV;
	}

	/* only parse routing algorithm name */
	last_err = -EINVAL;
	info_header = netlink_get_info(ifindex, BATADV_CMD_GET_ORIGINATORS, NULL);
	free(info_header);

	if (strlen(algo_name_buf) == 0)
		return last_err;

	if (!strcmp("BATMAN_IV", algo_name_buf))
		header = "   Originator        last-seen (#/255) Nexthop           [outgoingIF]\n";
	if (!strcmp("BATMAN_V", algo_name_buf))
		header = "   Originator        last-seen ( throughput)  Nexthop           [outgoingIF]\n";

	if (!header)
		return -EINVAL;

	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval, header,
				    BATADV_CMD_GET_ORIGINATORS,
				    originators_callback);
}

int netlink_print_neighbors(char *mesh_iface, char *orig_iface, int read_opts,
			    float orig_timeout,
			    float watch_interval)
{
	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval,
				    "IF             Neighbor              last-seen\n",
				    BATADV_CMD_GET_NEIGHBORS,
				    neighbors_callback);
}

int netlink_print_transglobal(char *mesh_iface, char *orig_iface,
			      int read_opts, float orig_timeout,
			      float watch_interval)
{
	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval,
				    "   Client             VID Flags Last ttvn     Via        ttvn  (CRC       )\n",
				    BATADV_CMD_GET_TRANSTABLE_GLOBAL,
				    transglobal_callback);
}

int netlink_print_translocal(char *mesh_iface, char *orig_iface, int read_opts,
			     float orig_timeout,
			     float watch_interval)
{
	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval,
				    "Client             VID Flags    Last seen (CRC       )\n",
				    BATADV_CMD_GET_TRANSTABLE_LOCAL,
				    translocal_callback);
}

int netlink_print_gateways(char *mesh_iface, char *orig_iface, int read_opts,
			   float orig_timeout,
			   float watch_interval)
{	char *header = NULL;
	char *info_header;
	int ifindex;

	ifindex = if_nametoindex(mesh_iface);
	if (!ifindex) {
		fprintf(stderr, "Interface %s is unknown\n", mesh_iface);
		return -ENODEV;
	}

	/* only parse routing algorithm name */
	last_err = -EINVAL;
	info_header = netlink_get_info(ifindex, BATADV_CMD_GET_ORIGINATORS, NULL);
	free(info_header);

	if (strlen(algo_name_buf) == 0)
		return last_err;

	if (!strcmp("BATMAN_IV", algo_name_buf))
		header = "  Router            ( TQ) Next Hop          [outgoingIf]  Bandwidth\n";
	if (!strcmp("BATMAN_V", algo_name_buf))
		header = "  Router            ( throughput) Next Hop          [outgoingIf]  Bandwidth\n";

	if (!header)
		return -EINVAL;

	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval,
				    header,
				    BATADV_CMD_GET_GATEWAYS,
				    gateways_callback);
}

int netlink_print_bla_claim(char *mesh_iface, char *orig_iface, int read_opts,
			    float orig_timeout,
			    float watch_interval)
{
	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval,
				    "Client               VID      Originator        [o] (CRC   )\n",
				    BATADV_CMD_GET_BLA_CLAIM,
				    bla_claim_callback);
}

int netlink_print_bla_backbone(char *mesh_iface, char *orig_iface, int read_opts,
			       float orig_timeout, float watch_interval)
{
	return netlink_print_common(mesh_iface, orig_iface, read_opts,
				    orig_timeout, watch_interval,
				    "Originator           VID   last seen (CRC   )\n",
				    BATADV_CMD_GET_BLA_BACKBONE,
				    bla_backbone_callback);
}

static int nlquery_error_cb(struct sockaddr_nl *nla __maybe_unused,
			    struct nlmsgerr *nlerr, void *arg)
{
	struct nlquery_opts *query_opts = arg;

	query_opts->err = nlerr->error;

	return NL_STOP;
}

static int nlquery_stop_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	int *error = nlmsg_data(nlh);

	if (*error)
		query_opts->err = *error;

	return NL_STOP;
}

static int netlink_query_common(const char *mesh_iface, uint8_t nl_cmd,
				nl_recvmsg_msg_cb_t callback, int flags,
				struct nlquery_opts *query_opts)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int ifindex;
	int family;
	int ret;

	query_opts->err = 0;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	ret = genl_connect(sock);
	if (ret < 0) {
		query_opts->err = ret;
		goto err_free_sock;
	}

	family = genl_ctrl_resolve(sock, BATADV_NL_NAME);
	if (family < 0) {
		query_opts->err = -EOPNOTSUPP;
		goto err_free_sock;
	}

	ifindex = if_nametoindex(mesh_iface);
	if (!ifindex) {
		query_opts->err = -ENODEV;
		goto err_free_sock;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		query_opts->err = -ENOMEM;
		goto err_free_sock;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback, query_opts);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nlquery_stop_cb, query_opts);
	nl_cb_err(cb, NL_CB_CUSTOM, nlquery_error_cb, query_opts);

	msg = nlmsg_alloc();
	if (!msg) {
		query_opts->err = -ENOMEM;
		goto err_free_cb;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, flags,
		    nl_cmd, 1);

	nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, ifindex);
	nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);

	nl_recvmsgs(sock, cb);

err_free_cb:
	nl_cb_put(cb);
err_free_sock:
	nl_socket_free(sock);

	return query_opts->err;
}

static const int translate_mac_netlink_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_ORIG_ADDRESS,
};

struct translate_mac_netlink_opts {
	struct ether_addr mac;
	bool found;
	struct nlquery_opts query_opts;
};

static int translate_mac_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct translate_mac_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	uint8_t *addr;
	uint8_t *orig;

	opts = container_of(query_opts, struct translate_mac_netlink_opts,
			    query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_GLOBAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (missing_mandatory_attrs(attrs, translate_mac_netlink_mandatory,
				    ARRAY_SIZE(translate_mac_netlink_mandatory)))
		return NL_OK;

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	if (memcmp(&opts->mac, addr, ETH_ALEN) != 0)
		return NL_OK;

	memcpy(&opts->mac, orig, ETH_ALEN);
	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int translate_mac_netlink(const char *mesh_iface, const struct ether_addr *mac,
			  struct ether_addr *mac_out)
{
	struct translate_mac_netlink_opts opts = {
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	memcpy(&opts.mac, mac, ETH_ALEN);

	ret = netlink_query_common(mesh_iface,
				   BATADV_CMD_GET_TRANSTABLE_GLOBAL,
			           translate_mac_netlink_cb, NLM_F_DUMP,
				   &opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	memcpy(mac_out, &opts.mac, ETH_ALEN);

	return 0;
}

static const int get_nexthop_netlink_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_HARD_IFINDEX,
};

struct get_nexthop_netlink_opts {
	struct ether_addr mac;
	uint8_t *nexthop;
	char *ifname;
	bool found;
	struct nlquery_opts query_opts;
};

static int get_nexthop_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct get_nexthop_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	const uint8_t *orig;
	const uint8_t *neigh;
	uint32_t index;
	const char *ifname;

	opts = container_of(query_opts, struct get_nexthop_netlink_opts,
			    query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (missing_mandatory_attrs(attrs, get_nexthop_netlink_mandatory,
				    ARRAY_SIZE(get_nexthop_netlink_mandatory)))
		return NL_OK;

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	neigh = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);
	index = nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	if (memcmp(&opts->mac, orig, ETH_ALEN) != 0)
		return NL_OK;

	/* save result */
	memcpy(opts->nexthop, neigh, ETH_ALEN);
	ifname = if_indextoname(index, opts->ifname);
	if (!ifname)
		return NL_OK;

	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int get_nexthop_netlink(const char *mesh_iface, const struct ether_addr *mac,
			uint8_t *nexthop, char *ifname)
{
	struct get_nexthop_netlink_opts opts = {
		.nexthop = 0,
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	memcpy(&opts.mac, mac, ETH_ALEN);
	opts.nexthop = nexthop;
	opts.ifname = ifname;

	ret = netlink_query_common(mesh_iface,  BATADV_CMD_GET_ORIGINATORS,
			           get_nexthop_netlink_cb, NLM_F_DUMP,
				   &opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	return 0;
}

static const int get_primarymac_netlink_mandatory[] = {
	BATADV_ATTR_HARD_ADDRESS,
};

struct get_primarymac_netlink_opts {
	uint8_t *primarymac;
	bool found;
	struct nlquery_opts query_opts;
};

static int get_primarymac_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct get_primarymac_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	const uint8_t *primary_mac;

	opts = container_of(query_opts, struct get_primarymac_netlink_opts,
			    query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_MESH_INFO)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (missing_mandatory_attrs(attrs, get_primarymac_netlink_mandatory,
				    ARRAY_SIZE(get_primarymac_netlink_mandatory)))
		return NL_OK;

	primary_mac = nla_data(attrs[BATADV_ATTR_HARD_ADDRESS]);

	/* save result */
	memcpy(opts->primarymac, primary_mac, ETH_ALEN);

	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int get_primarymac_netlink(const char *mesh_iface, uint8_t *primarymac)
{
	struct get_primarymac_netlink_opts opts = {
		.primarymac = 0,
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	opts.primarymac = primarymac;

	ret = netlink_query_common(mesh_iface, BATADV_CMD_GET_MESH_INFO,
			           get_primarymac_netlink_cb, 0,
				   &opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	return 0;
}
