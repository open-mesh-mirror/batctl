/*
 * Copyright (C) 2012 B.A.T.M.A.N. contributors:
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


#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include "main.h"
#include "ioctl.h"
#include "debugfs.h"

typedef unsigned long long u64;

const char proc_net_dev_path[] = "/proc/net/dev";

static int statistics_common_get(char *mesh_iface)
{
	FILE *fp;
	char iface[IFNAMSIZ + 1], *line_ptr = NULL;;
	unsigned long long rx_bytes, rx_packets, tx_bytes, tx_packets;
	unsigned long tx_errors;
	size_t len = 0;
	int res, ret = EXIT_FAILURE;

	rx_bytes = rx_packets = tx_bytes = tx_packets = tx_errors = 0;

	fp = fopen(proc_net_dev_path, "r");
	if (!fp) {
		printf("Error - can't open '%s' for read: %s\n",
		       proc_net_dev_path, strerror(errno));
		goto out;
	}

	while (getline(&line_ptr, &len, fp) != -1) {
		res = sscanf(line_ptr, " %" STR(IFNAMSIZ) "[^: \t]: %llu %llu %*d %*d %*d %*d %*d %*d %llu %llu %lu\n",
			     iface, &rx_bytes, &rx_packets, &tx_bytes, &tx_packets, &tx_errors);

		if (res != 6)
			continue;

		if (strcmp(iface, mesh_iface) != 0)
			continue;

		printf("\t%.*s: %llu\n", ETH_GSTRING_LEN, "tx", tx_packets);
		printf("\t%.*s: %llu\n", ETH_GSTRING_LEN, "tx_bytes", tx_bytes);
		printf("\t%.*s: %lu\n", ETH_GSTRING_LEN, "tx_errors", tx_errors);
		printf("\t%.*s: %llu\n", ETH_GSTRING_LEN, "rx", rx_packets);
		printf("\t%.*s: %llu\n", ETH_GSTRING_LEN, "rx_bytes", rx_bytes);
		ret = EXIT_SUCCESS;
		goto out;
	}

	printf("Error - interface '%s' not found\n", mesh_iface);

out:
	fclose(fp);
	free(line_ptr);
	return ret;
}

/* code borrowed from ethtool */
static int statistics_custom_get(int fd, struct ifreq *ifr)
{
	struct ethtool_drvinfo drvinfo;
	struct ethtool_gstrings *strings = NULL;
	struct ethtool_stats *stats = NULL;
	unsigned int n_stats, sz_str, sz_stats, i;
	int err, ret = EXIT_FAILURE;

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	ifr->ifr_data = (caddr_t)&drvinfo;
	err = ioctl(fd, SIOCETHTOOL, ifr);
	if (err < 0) {
		printf("Error - can't open driver information: %s\n", strerror(errno));
		goto out;
	}

	n_stats = drvinfo.n_stats;
	if (n_stats < 1)
		goto success;

	sz_str = n_stats * ETH_GSTRING_LEN;
	sz_stats = n_stats * sizeof(u64);

	strings = calloc(1, sz_str + sizeof(struct ethtool_gstrings));
	stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));
	if (!strings || !stats) {
		printf("Error - out of memory\n");
		goto out;
	}

	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = ETH_SS_STATS;
	strings->len = n_stats;
	ifr->ifr_data = (caddr_t)strings;
	err = ioctl(fd, SIOCETHTOOL, ifr);
	if (err < 0) {
		printf("Error - can't get stats strings information: %s\n", strerror(errno));
		goto out;
	}

	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = n_stats;
	ifr->ifr_data = (caddr_t) stats;
	err = ioctl(fd, SIOCETHTOOL, ifr);
	if (err < 0) {
		printf("Error - can't get stats information: %s\n", strerror(errno));
		goto out;
	}

	for (i = 0; i < n_stats; i++) {
		printf("\t%.*s: %llu\n", ETH_GSTRING_LEN,
		       &strings->data[i * ETH_GSTRING_LEN], stats->data[i]);
	}

success:
	ret = EXIT_SUCCESS;

out:
	free(strings);
	free(stats);
	return ret;
}

int ioctl_statistics_get(char *mesh_iface)
{
	struct ifreq ifr;
	int fd = -1, ret = EXIT_FAILURE;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, mesh_iface);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("Error - can't open socket: %s\n", strerror(errno));
		goto out;
	}

	ret = statistics_common_get(mesh_iface);
	if (ret != EXIT_SUCCESS)
		goto out;

	ret = statistics_custom_get(fd, &ifr);

out:
	if (fd >= 0)
		close(fd);
	return ret;
}
