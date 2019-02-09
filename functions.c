// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2007-2019  B.A.T.M.A.N. contributors:
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


#include <netinet/ether.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <net/ethernet.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/syscall.h>
#include <errno.h>
#include <net/if.h>
#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <time.h>

#include "main.h"
#include "functions.h"
#include "bat-hosts.h"
#include "sys.h"
#include "debug.h"
#include "debugfs.h"
#include "netlink.h"

#define PATH_BUFF_LEN 400

static struct timespec start_time;
static char *host_name;
char *line_ptr = NULL;

void start_timer(void)
{
	clock_gettime(CLOCK_MONOTONIC, &start_time);
}

double end_timer(void)
{
	struct timespec end_time, diff;

	clock_gettime(CLOCK_MONOTONIC, &end_time);
	diff.tv_sec = end_time.tv_sec - start_time.tv_sec;
	diff.tv_nsec = end_time.tv_nsec - start_time.tv_nsec;

	if (diff.tv_nsec < 0) {
		diff.tv_sec--;
		diff.tv_nsec += 1000000000;
	}

	return (((double)diff.tv_sec * 1000) + ((double)diff.tv_nsec / 1000000));
}

char *ether_ntoa_long(const struct ether_addr *addr)
{
	static char asc[18];

	sprintf(asc, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr->ether_addr_octet[0], addr->ether_addr_octet[1],
		addr->ether_addr_octet[2], addr->ether_addr_octet[3],
		addr->ether_addr_octet[4], addr->ether_addr_octet[5]);

	return asc;
}

char *get_name_by_macaddr(struct ether_addr *mac_addr, int read_opt)
{
	struct bat_host *bat_host = NULL;

	if (read_opt & USE_BAT_HOSTS)
		bat_host = bat_hosts_find_by_mac((char *)mac_addr);

	if (!bat_host)
		host_name = ether_ntoa_long((struct ether_addr *)mac_addr);
	else
		host_name = bat_host->name;

	return host_name;
}

char *get_name_by_macstr(char *mac_str, int read_opt)
{
	struct ether_addr *mac_addr;

	mac_addr = ether_aton(mac_str);
	if (!mac_addr)
		return mac_str;

	return get_name_by_macaddr(mac_addr, read_opt);
}

int file_exists(const char *fpath)
{
	struct stat st;

	return stat(fpath, &st) == 0;
}

static void file_open_problem_dbg(const char *dir, const char *full_path)
{
	struct stat st;

	if (strstr(dir, "/sys/")) {
		if (stat("/sys/", &st) != 0) {
			fprintf(stderr, "Error - the folder '/sys/' was not found on the system\n");
			fprintf(stderr, "Please make sure that the sys filesystem is properly mounted\n");
			return;
		}
	}

	if (!file_exists(module_ver_path)) {
		fprintf(stderr, "Error - batman-adv module has not been loaded\n");
		return;
	}

	fprintf(stderr, "Error - can't open file '%s': %s\n", full_path, strerror(errno));
	fprintf(stderr, "The option you called seems not to be compiled into your batman-adv kernel module.\n");
	fprintf(stderr, "Consult the README if you wish to learn more about compiling options into batman-adv.\n");
}

static int str_is_mcast_addr(char *addr)
{
	struct ether_addr *mac_addr = ether_aton(addr);

	return !mac_addr ? 0 :
		mac_addr->ether_addr_octet[0] & 0x01;
}

static bool ether_addr_valid(const uint8_t *addr)
{
	/* no multicast address */
	if (addr[0] & 0x01)
		return false;

	/* no zero address */
	if ((addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]) == 0)
		return false;

	return true;
}

int read_file(const char *dir, const char *fname, int read_opt,
	      float orig_timeout, float watch_interval, size_t header_lines)
{
	struct ether_addr *mac_addr;
	struct bat_host *bat_host;
	int res = EXIT_FAILURE;
	float last_seen;
	char full_path[500], *buff_ptr, *space_ptr, extra_char;
	size_t len = 0;
	FILE *fp = NULL;
	size_t line;

	if (read_opt & USE_BAT_HOSTS)
		bat_hosts_init(read_opt);

	snprintf(full_path, sizeof(full_path), "%s%s", dir, fname);

open:
	line = 0;
	fp = fopen(full_path, "r");

	if (!fp) {
		if (!(read_opt & SILENCE_ERRORS))
			file_open_problem_dbg(dir, full_path);

		goto out;
	}

	if (read_opt & CLR_CONT_READ)
		/* clear screen, set cursor back to 0,0 */
		printf("\033[2J\033[0;0f");

read:
	while (getline(&line_ptr, &len, fp) != -1) {
		if (line++ < header_lines && read_opt & SKIP_HEADER)
			continue;

		/* the buffer will be handled elsewhere */
		if (read_opt & USE_READ_BUFF)
			break;

		/* skip timed out originators */
		if (read_opt & NO_OLD_ORIGS)
			if (sscanf(line_ptr, "%*s %f", &last_seen)
			    && (last_seen > orig_timeout))
				continue;

		/* translation table: skip multicast */
		if (line > header_lines &&
		    read_opt & UNICAST_ONLY &&
		    strlen(line_ptr) > strlen(" * xx:xx:xx:") &&
		    str_is_mcast_addr(line_ptr+3))
			continue;

		/* translation table: skip unicast */
		if (line > header_lines &&
		    read_opt & MULTICAST_ONLY &&
		    strlen(line_ptr) > strlen(" * xx:xx:xx:") &&
		    !str_is_mcast_addr(line_ptr+3))
			continue;

		if (!(read_opt & USE_BAT_HOSTS)) {
			printf("%s", line_ptr);
			continue;
		}

		/* replace mac addresses with bat host names */
		buff_ptr = line_ptr;

		while ((space_ptr = strchr(buff_ptr, ' ')) != NULL) {

			*space_ptr = '\0';
			extra_char = '\0';

			if (strlen(buff_ptr) == ETH_STR_LEN + 1) {
				extra_char = buff_ptr[ETH_STR_LEN];
				switch (extra_char) {
				case ',':
				case ')':
					buff_ptr[ETH_STR_LEN] = '\0';
					break;
				default:
					extra_char = '\0';
					break;
				}
			}

			if (strlen(buff_ptr) != ETH_STR_LEN)
				goto print_plain_buff;

			mac_addr = ether_aton(buff_ptr);

			if (!mac_addr)
				goto print_plain_buff;

			bat_host = bat_hosts_find_by_mac((char *)mac_addr);

			if (!bat_host)
				goto print_plain_buff;

			if (read_opt & LOG_MODE)
				printf("%s", bat_host->name);
			else
				/* keep table format */
				printf("%17s", bat_host->name);

			goto written;

print_plain_buff:
			printf("%s", buff_ptr);

written:
			if (extra_char != '\0')
				printf("%c", extra_char);

			printf(" ");
			buff_ptr = space_ptr + 1;
		}

		printf("%s", buff_ptr);
	}

	if (read_opt & CONT_READ) {
		usleep(1000000 * watch_interval);
		goto read;
	}

	if (read_opt & CLR_CONT_READ) {
		if (fp)
			fclose(fp);
		usleep(1000000 * watch_interval);
		goto open;
	}

	if (line_ptr)
		res = EXIT_SUCCESS;

out:
	if (fp)
		fclose(fp);

	if (read_opt & USE_BAT_HOSTS)
		bat_hosts_free();

	return res;
}

int write_file(const char *dir, const char *fname, const char *arg1,
	       const char *arg2)
{
	int fd = -1, res = EXIT_FAILURE;
	char full_path[500];
	ssize_t write_len;

	snprintf(full_path, sizeof(full_path), "%s%s", dir, fname);

	fd = open(full_path, O_WRONLY);

	if (fd < 0) {
		file_open_problem_dbg(dir, full_path);
		goto out;
	}

	if (arg2)
		write_len = dprintf(fd, "%s %s", arg1, arg2);
	else
		write_len = write(fd, arg1, strlen(arg1) + 1);

	if (write_len < 0) {
		fprintf(stderr, "Error - can't write to file '%s': %s\n", full_path, strerror(errno));
		goto out;
	}

	res = EXIT_SUCCESS;

out:
	if (fd >= 0)
		close(fd);
	return res;
}

static int translate_mac_debugfs(const char *mesh_iface,
				 const struct ether_addr *mac,
				 struct ether_addr *mac_out)
{
	enum {
		tg_start,
		tg_mac,
		tg_via,
		tg_originator,
	} pos;
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;
	struct ether_addr *mac_tmp;
	FILE *f = NULL;
	size_t len = 0;
	char *line = NULL;
	char *input, *saveptr, *token;
	int line_invalid;
	bool found = false;

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt)
		return -EOPNOTSUPP;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_TRANSTABLE_GLOBAL, mesh_iface, full_path, sizeof(full_path));

	f = fopen(full_path, "r");
	if (!f)
		return -EOPNOTSUPP;

	while (getline(&line, &len, f) != -1) {
		line_invalid = 0;
		pos = tg_start;
		input = line;

		while ((token = strtok_r(input, " \t", &saveptr))) {
			input = NULL;

			switch (pos) {
			case tg_start:
				if (strcmp(token, "*") != 0)
					line_invalid = 1;
				else
					pos = tg_mac;
				break;
			case tg_mac:
				mac_tmp = ether_aton(token);
				if (!mac_tmp || memcmp(mac_tmp, mac,
						       ETH_ALEN) != 0)
					line_invalid = 1;
				else
					pos = tg_via;
				break;
			case tg_via:
				if (strcmp(token, "via") == 0)
					pos = tg_originator;
				break;
			case tg_originator:
				mac_tmp = ether_aton(token);
				if (!mac_tmp) {
					line_invalid = 1;
				} else {
					memcpy(mac_out, mac_tmp, ETH_ALEN);
					found = true;
					goto out;
				}
				break;
			}

			if (line_invalid)
				break;
		}
	}

out:
	if (f)
		fclose(f);
	free(line);

	if (found)
		return 0;
	else
		return -ENOENT;
}

struct ether_addr *translate_mac(const char *mesh_iface,
				 const struct ether_addr *mac)
{
	struct ether_addr in_mac;
	static struct ether_addr out_mac;
	struct ether_addr *mac_result;
	int ret;

	/* input mac has to be copied because it could be in the shared
	 * ether_aton buffer
	 */
	memcpy(&in_mac, mac, sizeof(in_mac));
	memcpy(&out_mac, mac, sizeof(out_mac));
	mac_result = &out_mac;

	if (!ether_addr_valid(in_mac.ether_addr_octet))
		return mac_result;

	ret = translate_mac_netlink(mesh_iface, &in_mac, mac_result);

	if (ret == -EOPNOTSUPP)
		translate_mac_debugfs(mesh_iface, &in_mac, mac_result);

	return mac_result;
}

int get_algoname(const char *mesh_iface, char *algoname, size_t algoname_len)
{
	char *path_buff;
	int ret;

	ret = get_algoname_netlink(mesh_iface, algoname, algoname_len);
	if (ret != -EOPNOTSUPP)
		return ret;

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		fprintf(stderr, "Error - could not allocate path buffer: out of memory ?\n");
		return -ENOMEM;
	}

	snprintf(path_buff, PATH_BUFF_LEN, SYS_ROUTING_ALGO_FMT, mesh_iface);
	ret = read_file("", path_buff, USE_READ_BUFF | SILENCE_ERRORS, 0, 0, 0);
	if (ret != EXIT_SUCCESS) {
		ret = -ENOENT;
		goto free_path_buf;
	}

	if (line_ptr[strlen(line_ptr) - 1] == '\n')
		line_ptr[strlen(line_ptr) - 1] = '\0';

	strncpy(algoname, line_ptr, algoname_len);
	if (algoname_len > 0)
		algoname[algoname_len - 1] = '\0';

free_path_buf:
	free(path_buff);

	free(line_ptr);
	line_ptr = NULL;

	return ret;
}

static int resolve_l3addr(int ai_family, const char *asc, void *l3addr)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *res;
	struct sockaddr_in *inet4;
	struct sockaddr_in6 *inet6;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;
	ret = getaddrinfo(asc, NULL, &hints, &res);
	if (ret)
		return -EADDRNOTAVAIL;

	if (res) {
		switch (ai_family) {
		case AF_INET:
			inet4 = (struct sockaddr_in *)res->ai_addr;
			memcpy(l3addr, &inet4->sin_addr.s_addr,
			       sizeof(inet4->sin_addr.s_addr));
			break;
		case AF_INET6:
			inet6 = (struct sockaddr_in6 *)res->ai_addr;
			memcpy(l3addr, &inet6->sin6_addr.s6_addr,
			       sizeof(inet6->sin6_addr.s6_addr));
			break;
		default:
			ret = -EINVAL;
		}
	}

	freeaddrinfo(res);
	return ret;
}

static void request_mac_resolve(int ai_family, const void *l3addr)
{
	const struct sockaddr *sockaddr;
	struct sockaddr_in inet4;
	struct sockaddr_in6 inet6;
	size_t sockaddr_len;
	int sock;
	char t = 0;

	sock = socket(ai_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return;

	switch (ai_family) {
	case AF_INET:
		memset(&inet4, 0, sizeof(inet4));
		inet4.sin_family = ai_family;
		inet4.sin_port = htons(9);
		memcpy(&inet4.sin_addr.s_addr, l3addr,
		       sizeof(inet4.sin_addr.s_addr));
		sockaddr = (const struct sockaddr *)&inet4;
		sockaddr_len = sizeof(inet4);
		break;
	case AF_INET6:
		memset(&inet6, 0, sizeof(inet6));
		inet6.sin6_family = ai_family;
		inet6.sin6_port = htons(9);
		memcpy(&inet6.sin6_addr.s6_addr, l3addr,
		       sizeof(inet6.sin6_addr.s6_addr));
		sockaddr = (const struct sockaddr *)&inet6;
		sockaddr_len = sizeof(inet6);
		break;
	default:
		close(sock);
		return;
	}

	sendto(sock, &t, sizeof(t), 0, sockaddr, sockaddr_len);
	close(sock);
}

struct resolve_mac_nl_arg {
	int ai_family;
	const void *l3addr;
	struct ether_addr *mac_result;
	int found;
};

static struct nla_policy neigh_policy[NDA_MAX+1] = {
	[NDA_CACHEINFO] = { .minlen = sizeof(struct nda_cacheinfo) },
	[NDA_PROBES]    = { .type = NLA_U32 },
};

static int resolve_mac_from_parse(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NDA_MAX + 1];
	struct ndmsg *nm;
	int ret;
	int l3_len;
	struct resolve_mac_nl_arg *nl_arg = arg;
	uint8_t *mac;
	uint8_t *l3addr;

	nm = nlmsg_data(nlmsg_hdr(msg));
	ret = nlmsg_parse(nlmsg_hdr(msg), sizeof(*nm), tb, NDA_MAX,
			  neigh_policy);
	if (ret < 0)
		goto err;

	if (nl_arg->ai_family != nm->ndm_family)
		goto err;

	switch (nl_arg->ai_family) {
	case AF_INET:
		l3_len = 4;
		break;
	case AF_INET6:
		l3_len = 16;
		break;
	default:
		l3_len = 0;
	}

	if (l3_len == 0)
		goto err;

	if (!tb[NDA_LLADDR] || !tb[NDA_DST])
		goto err;

	if (nla_len(tb[NDA_LLADDR]) != ETH_ALEN)
		goto err;

	if (nla_len(tb[NDA_DST]) != l3_len)
		goto err;

	mac = nla_data(tb[NDA_LLADDR]);
	l3addr = nla_data(tb[NDA_DST]);

	if (!ether_addr_valid(mac))
		goto err;

	if (memcmp(nl_arg->l3addr, l3addr, l3_len) == 0) {
		memcpy(nl_arg->mac_result, mac, ETH_ALEN);
		nl_arg->found = 1;
	}

err:
	if (nl_arg->found)
		return NL_STOP;
	else
		return NL_OK;
}

static struct ether_addr *resolve_mac_from_cache(int ai_family,
						 const void *l3addr)
{
	struct nl_sock *sock;
	struct ether_addr *mac_result = NULL;
	static struct ether_addr mac_tmp;
	int ret;
	struct rtgenmsg gmsg = {
		.rtgen_family = ai_family,
	};
	struct nl_cb *cb = NULL;
	struct resolve_mac_nl_arg arg = {
		.ai_family = ai_family,
		.l3addr = l3addr,
		.mac_result = &mac_tmp,
		.found = 0,
	};

	sock = nl_socket_alloc();
	if (!sock)
		goto err;

	ret = nl_connect(sock, NETLINK_ROUTE);
	if (ret < 0)
		goto err;

	ret = nl_send_simple(sock, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP,
			     &gmsg, sizeof(gmsg));
	if (ret < 0)
		goto err;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto err;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, resolve_mac_from_parse, &arg);
	ret = nl_recvmsgs(sock, cb);
	if (ret < 0)
		goto err;

	if (arg.found)
		mac_result = &mac_tmp;

err:
	if (cb)
		nl_cb_put(cb);
	if (sock)
		nl_socket_free(sock);

	return mac_result;
}

static struct ether_addr *resolve_mac_from_addr(int ai_family, const char *asc)
{
	uint8_t ipv4_addr[4];
	uint8_t ipv6_addr[16];
	void *l3addr;
	int ret;
	int retries = 5;
	struct ether_addr *mac_result = NULL;

	switch (ai_family) {
	case AF_INET:
		l3addr = ipv4_addr;
		break;
	case AF_INET6:
		l3addr = ipv6_addr;
		break;
	default:
		return NULL;
	}

	ret = resolve_l3addr(ai_family, asc, l3addr);
	if (ret < 0)
		return NULL;

	while (retries-- && !mac_result) {
		mac_result = resolve_mac_from_cache(ai_family, l3addr);
		if (!mac_result) {
			request_mac_resolve(ai_family, l3addr);
			usleep(200000);
		}
	}

	return mac_result;
}

struct ether_addr *resolve_mac(const char *asc)
{
	struct ether_addr *mac_result = NULL;
	static const int ai_families[] = {AF_INET, AF_INET6};
	size_t i;

	mac_result = ether_aton(asc);
	if (mac_result)
		goto out;

	for (i = 0; i < sizeof(ai_families) / sizeof(*ai_families); i++) {
		mac_result = resolve_mac_from_addr(ai_families[i], asc);
		if (mac_result)
			goto out;
	}

out:
	return mac_result;
}

struct vlan_get_link_nl_arg {
	char *iface;
	int vid;
};

static struct nla_policy info_data_link_policy[IFLA_MAX + 1] = {
	[IFLA_LINKINFO]	= { .type = NLA_NESTED },
	[IFLA_LINK]	= { .type = NLA_U32 },
};

static struct nla_policy info_data_link_info_policy[IFLA_INFO_MAX + 1] = {
	[IFLA_INFO_DATA]	= { .type = NLA_NESTED },
};

static struct nla_policy vlan_policy[IFLA_VLAN_MAX + 1] = {
	[IFLA_VLAN_ID]		= { .type = NLA_U16 },
};

/**
 * vlan_get_link_parse - parse a get_link rtnl message and extract the important
 *  data
 * @msg: the reply msg
 * @arg: pointer to the buffer which will store the return values
 *
 * Saves the vid  in arg::vid in case of success or -1 otherwise
 */
static int vlan_get_link_parse(struct nl_msg *msg, void *arg)
{
	struct vlan_get_link_nl_arg *nl_arg = arg;
	struct nlmsghdr *n = nlmsg_hdr(msg);
	struct nlattr *tb[IFLA_MAX + 1];
	struct nlattr *li[IFLA_INFO_MAX + 1];
	struct nlattr *vi[IFLA_VLAN_MAX + 1];
	int ret;
	int idx;

	if (!nlmsg_valid_hdr(n, sizeof(struct ifinfomsg)))
		return -NLE_MSG_TOOSHORT;

	ret = nlmsg_parse(n, sizeof(struct ifinfomsg), tb, IFLA_MAX,
			  info_data_link_policy);
	if (ret < 0)
		return ret;

	if (!tb[IFLA_LINK])
		return -NLE_MISSING_ATTR;

	/* parse subattributes linkinfo */
	if (!tb[IFLA_LINKINFO])
		return -NLE_MISSING_ATTR;

	ret = nla_parse_nested(li, IFLA_INFO_MAX, tb[IFLA_LINKINFO],
			       info_data_link_info_policy);
	if (ret < 0)
		return ret;

	if (!li[IFLA_INFO_KIND])
		return -NLE_MISSING_ATTR;

	if (strcmp(nla_data(li[IFLA_INFO_KIND]), "vlan") != 0)
		goto err;

	/* parse subattributes info_data for vlan */
	if (!li[IFLA_INFO_DATA])
		return -NLE_MISSING_ATTR;

	ret = nla_parse_nested(vi, IFLA_VLAN_MAX, li[IFLA_INFO_DATA],
			       vlan_policy);
	if (ret < 0)
		return ret;

	if (!vi[IFLA_VLAN_ID])
		return -NLE_MISSING_ATTR;

	/* get parent link name */
	idx = *(int *)nla_data(tb[IFLA_LINK]);

	if (!if_indextoname(idx, nl_arg->iface))
		goto err;

	/* get the corresponding vid */
	nl_arg->vid = *(int *)nla_data(vi[IFLA_VLAN_ID]);

err:
	if (nl_arg->vid >= 0)
		return NL_STOP;
	else
		return NL_OK;
}

/**
 * vlan_get_link - convert a VLAN interface into its parent one
 * @ifname: the interface to convert
 * @parent: buffer where the parent interface name will be written
 *  (minimum IF_NAMESIZE)
 *
 * Returns the vlan identifier on success or -1 on error
 */
static int vlan_get_link(const char *ifname, char *parent)
{
	struct nl_sock *sock;
	int ret;
	struct ifinfomsg ifinfo = {
		.ifi_family = AF_UNSPEC,
		.ifi_index = if_nametoindex(ifname),
	};
	struct nl_cb *cb = NULL;
	struct vlan_get_link_nl_arg arg = {
		.iface = parent,
		.vid = -1,
	};

	sock = nl_socket_alloc();
	if (!sock)
		goto err;

	ret = nl_connect(sock, NETLINK_ROUTE);
	if (ret < 0)
		goto err;

	ret = nl_send_simple(sock, RTM_GETLINK, NLM_F_REQUEST,
			     &ifinfo, sizeof(ifinfo));
	if (ret < 0)
		goto err;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto err;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, vlan_get_link_parse, &arg);
	ret = nl_recvmsgs(sock, cb);
	if (ret < 0)
		goto err;

err:
	if (cb)
		nl_cb_put(cb);
	if (sock)
		nl_socket_free(sock);

	return arg.vid;
}

int query_rtnl_link(int ifindex, nl_recvmsg_msg_cb_t func, void *arg)
{
	struct ifinfomsg rt_hdr = {
		.ifi_family = IFLA_UNSPEC,
	};
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int err = 0;
	int ret;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	ret = nl_connect(sock, NETLINK_ROUTE);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_sock;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		err = -ENOMEM;
		goto err_free_sock;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, func, arg);

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg) {
		err = -ENOMEM;
		goto err_free_cb;
	}

	ret = nlmsg_append(msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_u32(msg, IFLA_MASTER, ifindex);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto err_free_msg;

	nl_recvmsgs(sock, cb);

err_free_msg:
	nlmsg_free(msg);
err_free_cb:
	nl_cb_put(cb);
err_free_sock:
	nl_socket_free(sock);

	return err;
}

static int ack_errno_handler(struct sockaddr_nl *nla __maybe_unused,
			     struct nlmsgerr *nlerr,
			     void *arg)
{
	int *err = arg;

	*err = nlerr->error;

	return NL_STOP;
}

static int ack_wait_handler(struct nl_msg *msg __maybe_unused,
			    void *arg __maybe_unused)
{
	return NL_STOP;
}

int netlink_simple_request(struct nl_msg *msg)
{
	struct nl_sock *sock;
	struct nl_cb *cb;
	int err = 0;
	int ret;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	ret = nl_connect(sock, NETLINK_ROUTE);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_sock;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		err = -ENOMEM;
		goto err_free_sock;
	}

	nl_cb_err(cb, NL_CB_CUSTOM, ack_errno_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_wait_handler, NULL);

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto err_free_cb;

	// ack_errno_handler sets err on errors
	err = 0;
	nl_recvmsgs(sock, cb);

err_free_cb:
	nl_cb_put(cb);
err_free_sock:
	nl_socket_free(sock);

	return err;
}

int translate_mesh_iface(struct state *state)
{
	state->vid = vlan_get_link(state->arg_iface, state->mesh_iface);
	if (state->vid < 0) {
		/* if there is no iface then the argument must be the
		 * mesh interface
		 */
		snprintf(state->mesh_iface, sizeof(state->mesh_iface), "%s",
			 state->arg_iface);
	}

	return 0;
}

int check_mesh_iface(struct state *state)
{
	char path_buff[PATH_BUFF_LEN];
	int ret = -1;
	DIR *dir;

	/* use the parent interface if this is a VLAN */
	if (state->vid >= 0)
		snprintf(path_buff, PATH_BUFF_LEN, SYS_VLAN_PATH,
			 state->mesh_iface, state->vid);
	else
		snprintf(path_buff, PATH_BUFF_LEN, SYS_BATIF_PATH_FMT,
			 state->mesh_iface);

	/* try to open the mesh sys directory */
	dir = opendir(path_buff);
	if (!dir)
		goto out;

	closedir(dir);

	state->mesh_ifindex = if_nametoindex(state->mesh_iface);
	if (state->mesh_ifindex == 0)
		goto out;

	ret = 0;
out:
	return ret;
}

int check_mesh_iface_ownership(char *mesh_iface, char *hard_iface)
{
	char path_buff[PATH_BUFF_LEN];
	int res;

	/* check if this device actually belongs to the mesh interface */
	snprintf(path_buff, sizeof(path_buff), SYS_MESH_IFACE_FMT, hard_iface);
	res = read_file("", path_buff, USE_READ_BUFF | SILENCE_ERRORS, 0, 0, 0);
	if (res != EXIT_SUCCESS) {
		fprintf(stderr, "Error - the directory '%s' could not be read: %s\n",
			path_buff, strerror(errno));
		fprintf(stderr, "Is the batman-adv module loaded and sysfs mounted ?\n");
		return EXIT_FAILURE;
	}

	if (line_ptr[strlen(line_ptr) - 1] == '\n')
		line_ptr[strlen(line_ptr) - 1] = '\0';

	if (strcmp(line_ptr, mesh_iface) != 0) {
		fprintf(stderr, "Error - interface %s is part of batman network %s, not %s\n",
			hard_iface, line_ptr, mesh_iface);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int get_random_bytes_syscall(void *buf __maybe_unused,
				    size_t buflen __maybe_unused)
{
#ifdef SYS_getrandom
	return syscall(SYS_getrandom, buf, buflen, 0);
#else
	return -EOPNOTSUPP;
#endif
}

static int get_random_bytes_urandom(void *buf, size_t buflen)
{
	int fd;
	ssize_t r;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -EOPNOTSUPP;

	r = read(fd, buf, buflen);
	close(fd);
	if (r < 0)
		return -EOPNOTSUPP;

	if ((size_t)r != buflen)
		return -EOPNOTSUPP;

	return 0;
}

static int get_random_bytes_fallback(void *buf, size_t buflen)
{
	struct timespec now;
	static int initialized = 0;
	size_t i;
	uint8_t *bufc = buf;

	/* this is not a good source for randomness */
	if (!initialized) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		srand(now.tv_sec ^ now.tv_nsec);
		initialized = 1;
	}

	for (i = 0; i < buflen; i++)
		bufc[i] = rand() & 0xff;

	return 0;
}

void get_random_bytes(void *buf, size_t buflen)
{
	int ret;

	ret = get_random_bytes_syscall(buf, buflen);
	if (ret != -EOPNOTSUPP)
		return;

	ret = get_random_bytes_urandom(buf, buflen);
	if (ret != -EOPNOTSUPP)
		return;

	get_random_bytes_fallback(buf, buflen);
}

void check_root_or_die(const char *cmd)
{
	if (geteuid() != 0) {
		fprintf(stderr, "Error - you must be root to run '%s' !\n", cmd);
		exit(EXIT_FAILURE);
	}
}

bool parse_throughput(char *buff, const char *description, uint32_t *throughput)
{
	enum batadv_bandwidth_units bw_unit_type = BATADV_BW_UNIT_KBIT;
	uint64_t lthroughput;
	char *tmp_ptr;
	char *endptr;

	if (strlen(buff) > 4) {
		tmp_ptr = buff + strlen(buff) - 4;

		if (strncasecmp(tmp_ptr, "mbit", 4) == 0)
			bw_unit_type = BATADV_BW_UNIT_MBIT;

		if (strncasecmp(tmp_ptr, "kbit", 4) == 0 ||
		    bw_unit_type == BATADV_BW_UNIT_MBIT)
			*tmp_ptr = '\0';
	}

	lthroughput = strtoull(buff, &endptr, 10);
	if (!endptr || *endptr != '\0') {
		fprintf(stderr, "Invalid throughput speed for %s: %s\n",
			description, buff);
		return false;
	}

	switch (bw_unit_type) {
	case BATADV_BW_UNIT_MBIT:
		/* prevent overflow */
		if (UINT64_MAX / 10 < lthroughput) {
			fprintf(stderr,
				"Throughput speed for %s too large: %s\n",
				description, buff);
			return false;
		}

		lthroughput *= 10;
		break;
	case BATADV_BW_UNIT_KBIT:
	default:
		lthroughput = lthroughput / 100;
		break;
	}

	if (lthroughput > UINT32_MAX) {
		fprintf(stderr, "Throughput speed for %s too large: %s\n",
			description, buff);
		return false;
	}

	*throughput = lthroughput;

	return true;
}
