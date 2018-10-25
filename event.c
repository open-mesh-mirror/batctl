// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2018  B.A.T.M.A.N. contributors:
 *
 * Sven Eckelmann <sven@narfation.org>
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

#include <errno.h>
#include <getopt.h>
#include <netinet/if_ether.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>

#include "batadv_packet.h"
#include "batman_adv.h"
#include "bat-hosts.h"
#include "debug.h"
#include "functions.h"
#include "genl.h"
#include "main.h"
#include "netlink.h"

enum event_time_mode {
	EVENT_TIME_NO,
	EVENT_TIME_LOCAL,
	EVENT_TIME_RELATIVE,
};

struct event_args {
	enum event_time_mode mode;
	struct timeval tv;
};

static void event_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] event [parameters]\n");
	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -h print this help\n");
	fprintf(stderr, " \t -t print local timestamp\n");
	fprintf(stderr, " \t -r print relative timestamp\n");
}

static int event_prepare(struct state *state)
{
	int ret;
	int mcid;

	if (!state->sock)
		return -EOPNOTSUPP;

	mcid = nl_get_multicast_id(state->sock, BATADV_NL_NAME,
				   BATADV_NL_MCAST_GROUP_TPMETER);
	if (mcid < 0) {
		fprintf(stderr, "Failed to resolve batadv tp_meter multicast group: %d\n",
			mcid);
		/* ignore error for now */
		goto skip_tp_meter;
	}

	ret = nl_socket_add_membership(state->sock, mcid);
	if (ret) {
		fprintf(stderr, "Failed to join batadv tp_meter multicast group: %d\n",
			ret);
		/* ignore error for now */
		goto skip_tp_meter;
	}

skip_tp_meter:

	return 0;
}

static int no_seq_check(struct nl_msg *msg __maybe_unused,
			void *arg __maybe_unused)
{
	return NL_OK;
}

static const int tp_meter_mandatory[] = {
	BATADV_ATTR_TPMETER_COOKIE,
	BATADV_ATTR_TPMETER_RESULT,
};

static void event_parse_tp_meter(struct nlattr **attrs)
{
	const char *result_str;
	uint32_t cookie;
	uint8_t result;

	/* ignore entry when attributes are missing */
	if (missing_mandatory_attrs(attrs, tp_meter_mandatory,
				    ARRAY_SIZE(tp_meter_mandatory)))
		return;

	cookie = nla_get_u32(attrs[BATADV_ATTR_TPMETER_COOKIE]);
	result = nla_get_u8(attrs[BATADV_ATTR_TPMETER_RESULT]);

	switch (result) {
	case BATADV_TP_REASON_DST_UNREACHABLE:
		result_str = "Destination unreachable";
		break;
	case BATADV_TP_REASON_RESEND_LIMIT:
		result_str = "The number of retry for the same window exceeds the limit, test aborted";
		break;
	case BATADV_TP_REASON_ALREADY_ONGOING:
		result_str = "Cannot run two test towards the same node";
		break;
	case BATADV_TP_REASON_MEMORY_ERROR:
		result_str = "Kernel cannot allocate memory, aborted";
		break;
	case BATADV_TP_REASON_TOO_MANY:
		result_str = "Too many ongoing sessions";
		break;
	case BATADV_TP_REASON_CANCEL:
		result_str = "CANCEL received: test aborted";
		break;
	case BATADV_TP_REASON_COMPLETE:
		result_str = "complete";
		break;
	default:
		result_str = "unknown";
		break;
	}

	printf("tp_meter 0x%08x: %s\n", cookie, result_str);
}

static unsigned long long get_timestamp(struct event_args *event_args)
{
	unsigned long long prevtime = 0;
	unsigned long long now;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	now = 1000000ULL * tv.tv_sec + tv.tv_usec;

	if (event_args->mode == EVENT_TIME_RELATIVE) {
		prevtime = 1000000ULL * event_args->tv.tv_sec + event_args->tv.tv_usec;
		event_args->tv = tv;
	}

	return now - prevtime;
}

static int event_parse(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[NUM_BATADV_ATTR];
	struct event_args *event_args = arg;
	unsigned long long timestamp;
	struct genlmsghdr *ghdr;

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		fputs("Received invalid data from kernel.\n", stderr);
		return NL_OK;
	}

	if (event_args->mode != EVENT_TIME_NO) {
		timestamp = get_timestamp(event_args);
		printf("%llu.%06llu: ", timestamp / 1000000, timestamp % 1000000);
	}

	switch (ghdr->cmd) {
	case BATADV_CMD_TP_METER:
		event_parse_tp_meter(attrs);
		break;
	default:
		printf("Received unknown event %u\n", ghdr->cmd);
		break;
	}

	return NL_OK;
}

static int event(struct state *state, int argc, char **argv)
{
	struct event_args event_args = {
		.mode = EVENT_TIME_NO,
	};
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "htr")) != -1) {
		switch (opt) {
		case 'h':
			event_usage();
			return EXIT_SUCCESS;
		case 't':
			event_args.mode = EVENT_TIME_LOCAL;
			break;
		case 'r':
			event_args.mode = EVENT_TIME_RELATIVE;
			break;
		default:
			event_usage();
			return  EXIT_FAILURE;
		}
	}

	ret = event_prepare(state);
	if (ret < 0) {
		fprintf(stderr, "Failed to prepare event netlink: %s (%d)\n",
			strerror(-ret), -ret);
		return 1;
	}

	if (event_args.mode == EVENT_TIME_RELATIVE)
		get_timestamp(&event_args);

	nl_cb_set(state->cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
	nl_cb_set(state->cb, NL_CB_VALID, NL_CB_CUSTOM, event_parse, &event_args);

	while (1)
		nl_recvmsgs(state->sock, state->cb);

	return 0;
}

COMMAND(SUBCOMMAND, event, "e", COMMAND_FLAG_NETLINK, NULL,
	"                  \tdisplay events from batman-adv");
