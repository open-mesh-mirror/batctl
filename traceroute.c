/* Copyright (C) 2007-2009 B.A.T.M.A.N. contributors:
 * Andreas Langer <a.langer@q-dsl.de>
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



#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "main.h"
#include "traceroute.h"
#include "functions.h"
#include "packet.h"
#include "bat-hosts.h"


#define TTL_MAX 50


void traceroute_usage(void)
{
	printf("Usage: batctl traceroute [options] mac|bat-host \n");
	printf("options:\n");
	printf(" \t -h print this help\n");
}

int traceroute(int argc, char **argv)
{
	struct icmp_packet icmp_packet_out, icmp_packet_in;
	struct bat_host *bat_host;
	struct ether_addr *dst_mac = NULL;
	struct timeval start, end, tv;
	fd_set read_socket;
	ssize_t read_len;
	char *dst_string, *mac_string, *return_mac, dst_reached = 0;
	int ret = EXIT_FAILURE, res, trace_fd = 0, i;
	int found_args = 1, optchar, seq_counter = 0;
	double time_delta = 0.0;

	while ((optchar = getopt(argc, argv, "h")) != -1) {
		switch (optchar) {
		case 'h':
			traceroute_usage();
			return EXIT_SUCCESS;
		default:
			traceroute_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args) {
		printf("Error - target mac address or bat-host name not specified\n");
		traceroute_usage();
		return EXIT_FAILURE;
	}

	dst_string = argv[found_args];
	bat_hosts_init();
	bat_host = bat_hosts_find_by_name(dst_string);

	if (bat_host)
		dst_mac = &bat_host->mac_addr;

	if (!dst_mac) {
		dst_mac = ether_aton(dst_string);

		if (!dst_mac) {
			printf("Error - the traceroute destination is not a mac address or bat-host name: %s\n", dst_string);
			goto out;
		}
	}

	mac_string = ether_ntoa(dst_mac);

	trace_fd = open(BAT_DEVICE, O_RDWR);

	if (trace_fd < 0) {
		printf("Error - can't open a connection to the batman adv kernel module via the device '%s': %s\n",
				BAT_DEVICE, strerror(errno));
		printf("Check whether the module is loaded and active.\n");
		goto out;
	}

	memcpy(&icmp_packet_out.dst, dst_mac, ETH_ALEN);
	icmp_packet_out.version = COMPAT_VERSION;
	icmp_packet_out.packet_type = BAT_ICMP;
	icmp_packet_out.msg_type = ECHO_REQUEST;
	icmp_packet_out.seqno = 0;

	printf("traceroute to %s (%s), %d hops max, %zd byte packets\n",
		dst_string, mac_string, TTL_MAX, sizeof(icmp_packet_out));

	for (icmp_packet_out.ttl = 0; !dst_reached && icmp_packet_out.ttl < TTL_MAX; icmp_packet_out.ttl++) {
		icmp_packet_out.seqno = htons(++seq_counter);

		for (i = 0; i < 3; i++) {
			if (write(trace_fd, (char *)&icmp_packet_out, sizeof(icmp_packet_out)) < 0) {
				printf("Error - can't write to batman adv kernel file '%s': %s\n", BAT_DEVICE, strerror(errno));
				continue;
			}

			gettimeofday(&start, (struct timezone*)0);

			tv.tv_sec = 2;
			tv.tv_usec = 0;

			FD_ZERO(&read_socket);
			FD_SET(trace_fd, &read_socket);

			res = select(trace_fd + 1, &read_socket, NULL, NULL, &tv);

			if (res <= 0) {
				printf(" * ");
				fflush(stdout);
				continue;
			}

			read_len = read(trace_fd, (char *)&icmp_packet_in, sizeof(icmp_packet_in));

			if (read_len < 0) {
				printf("Error - can't read from batman adv kernel file '%s': %s\n", BAT_DEVICE, strerror(errno));
				continue;
			}

			if ((size_t)read_len < sizeof(icmp_packet_in)) {
				printf("Warning - dropping received packet as it is smaller than expected (%zd): %zd\n",
					sizeof(icmp_packet_in), read_len);
				continue;
			}

			switch (icmp_packet_in.msg_type) {
			case ECHO_REPLY:
			case TTL_EXCEEDED:
				gettimeofday(&end, (struct timezone*)0);
				time_delta = time_diff(&start, &end);

				if (i > 0) {
					printf("  %.3f ms", time_delta);
					break;
				}

				return_mac = ether_ntoa((struct ether_addr *)icmp_packet_in.orig);
				bat_host = bat_hosts_find_by_mac((char *)icmp_packet_in.orig);

				if (!bat_host)
					printf("%u: %s %.3f ms",
						ntohs(icmp_packet_in.seqno), return_mac, time_delta);
				else
					printf("%u: %s (%s) %.3f ms",
						ntohs(icmp_packet_in.seqno),
						return_mac, bat_host->name, time_delta);

				if (icmp_packet_in.msg_type == ECHO_REPLY)
					dst_reached = 1;
			case DESTINATION_UNREACHABLE:
				printf("%s: Destination Host Unreachable\n", dst_string);
				break;
			case PARAMETER_PROBLEM:
				printf("Error - the batman adv kernel module version (%d) differs from ours (%d)\n",
						icmp_packet_in.ttl, COMPAT_VERSION);
				printf("Please make sure to compatible versions!\n");
				goto out;
			default:
				printf("Unknown message type %d len %zd received\n", icmp_packet_in.msg_type, read_len);
				break;
			}
		}

		printf("\n");
	}

	ret = EXIT_SUCCESS;

out:
	bat_hosts_free();
	if (trace_fd)
		close(trace_fd);
	return ret;
}
