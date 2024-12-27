// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <marek.lindner@mailbox.org>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>
#include <sys/select.h>
#include <sys/time.h>

#include "batadv_packet_compat.h"
#include "main.h"
#include "functions.h"
#include "bat-hosts.h"
#include "icmp_helper.h"

#define TTL_MAX 50
#define NUM_PACKETS 3

static void traceroute_usage(void)
{
	fprintf(stderr, "Usage: batctl [options] traceroute [parameters] mac|bat-host|host_name|IPv4_address\n");
	fprintf(stderr, "parameters:\n");
	fprintf(stderr, " \t -h print this help\n");
	fprintf(stderr, " \t -n don't convert addresses to bat-host names\n");
	fprintf(stderr, " \t -T don't try to translate mac to originator address\n");
}

static int traceroute(struct state *state, int argc, char **argv)
{
	struct batadv_icmp_packet icmp_packet_out;
	struct batadv_icmp_packet icmp_packet_in;
	struct ether_addr *dst_mac = NULL;
	double time_delta[NUM_PACKETS];
	int disable_translate_mac = 0;
	int read_opt = USE_BAT_HOSTS;
	struct bat_host *bat_host;
	int ret = EXIT_FAILURE;
	char dst_reached = 0;
	int seq_counter = 0;
	int found_args = 1;
	struct timeval tv;
	ssize_t read_len;
	char *dst_string;
	char *mac_string;
	char *return_mac;
	int optchar;
	int res;
	int i;

	while ((optchar = getopt(argc, argv, "hnT")) != -1) {
		switch (optchar) {
		case 'h':
			traceroute_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		case 'T':
			disable_translate_mac = 1;
			found_args += 1;
			break;
		default:
			traceroute_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args) {
		fprintf(stderr, "Error - target mac address or bat-host name not specified\n");
		traceroute_usage();
		return EXIT_FAILURE;
	}

	dst_string = argv[found_args];
	bat_hosts_init(read_opt);
	bat_host = bat_hosts_find_by_name(dst_string);

	if (bat_host)
		dst_mac = &bat_host->mac_addr;

	if (!dst_mac) {
		dst_mac = resolve_mac(dst_string);

		if (!dst_mac) {
			fprintf(stderr,
				"Error - mac address of the ping destination could not be resolved and is not a bat-host name: %s\n",
				dst_string);
			goto out;
		}
	}

	if (!disable_translate_mac)
		dst_mac = translate_mac(state, dst_mac);

	mac_string = ether_ntoa_long(dst_mac);

	icmp_interfaces_init();

	memset(&icmp_packet_out, 0, sizeof(icmp_packet_out));
	memcpy(&icmp_packet_out.dst, dst_mac, ETH_ALEN);
	icmp_packet_out.version = BATADV_COMPAT_VERSION;
	icmp_packet_out.packet_type = BATADV_ICMP;
	icmp_packet_out.msg_type = BATADV_ECHO_REQUEST;
	icmp_packet_out.seqno = 0;
	icmp_packet_out.reserved = 0;

	printf("traceroute to %s (%s), %d hops max, %zu byte packets\n",
	       dst_string, mac_string, TTL_MAX, sizeof(icmp_packet_out));

	for (icmp_packet_out.ttl = 1;
	     !dst_reached && icmp_packet_out.ttl < TTL_MAX;
	     icmp_packet_out.ttl++) {
		return_mac = NULL;
		bat_host = NULL;

		for (i = 0; i < NUM_PACKETS; i++) {
			icmp_packet_out.seqno = htons(++seq_counter);
			time_delta[i] = 0.0;

			res = icmp_interface_write(state,
						   (struct batadv_icmp_header *)&icmp_packet_out,
						   sizeof(icmp_packet_out));
			if (res < 0) {
				fprintf(stderr, "Error - can't send icmp packet: %s\n",
					strerror(-res));
				continue;
			}

read_packet:
			start_timer();

			tv.tv_sec = 2;
			tv.tv_usec = 0;

			read_len = icmp_interface_read((struct batadv_icmp_header *)&icmp_packet_in,
						       sizeof(icmp_packet_in), &tv);
			if (read_len <= 0)
				continue;

			if ((size_t)read_len < sizeof(icmp_packet_in)) {
				printf("Warning - dropping received packet as it is smaller than expected (%zu): %zd\n",
				       sizeof(icmp_packet_in), read_len);
				continue;
			}

			/* after receiving an unexpected seqno we keep waiting for our answer */
			if (htons(seq_counter) != icmp_packet_in.seqno)
				goto read_packet;

			switch (icmp_packet_in.msg_type) {
			case BATADV_ECHO_REPLY:
				dst_reached = 1;
				/* fall through */
			case BATADV_TTL_EXCEEDED:
				time_delta[i] = end_timer();

				if (!return_mac) {
					return_mac = ether_ntoa_long((struct ether_addr *)&icmp_packet_in.orig);

					if (read_opt & USE_BAT_HOSTS)
						bat_host = bat_hosts_find_by_mac((char *)&icmp_packet_in.orig);
				}

				break;
			case BATADV_DESTINATION_UNREACHABLE:
				printf("%s: Destination Host Unreachable\n", dst_string);
				goto out;
			case BATADV_PARAMETER_PROBLEM:
				fprintf(stderr, "Error - the batman adv kernel module version (%d) differs from ours (%d)\n",
					icmp_packet_in.version, BATADV_COMPAT_VERSION);
				fprintf(stderr, "Please make sure to use compatible versions!\n");
				goto out;
			default:
				printf("Unknown message type %d len %zd received\n",
				       icmp_packet_in.msg_type, read_len);
				break;
			}
		}

		if (!bat_host)
			printf("%2hhu: %s", icmp_packet_out.ttl,
			       (return_mac ? return_mac : "*"));
		else
			printf("%2hhu: %s (%s)",
			       icmp_packet_out.ttl,
			       bat_host->name, return_mac);

		for (i = 0; i < NUM_PACKETS; i++) {
			if (time_delta[i])
				printf("  %.3f ms", time_delta[i]);
			else
				printf("   *");
		}

		printf("\n");
	}

	ret = EXIT_SUCCESS;

out:
	icmp_interfaces_clean();
	bat_hosts_free();
	return ret;
}

COMMAND(SUBCOMMAND_MIF, traceroute, "tr",
	COMMAND_FLAG_MESH_IFACE | COMMAND_FLAG_NETLINK, NULL,
	"<destination>     \ttraceroute another batman adv host via layer 2");
