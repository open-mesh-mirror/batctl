/*
 * Copyright (C) 2007-2014 B.A.T.M.A.N. contributors:
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
 */


#include <netinet/ether.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <stdint.h>
#include <linux/netlink.h>
#include <net/ethernet.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <sys/uio.h>
#include <errno.h>
#include <net/if.h>

#include "main.h"
#include "functions.h"
#include "bat-hosts.h"
#include "sys.h"
#include "debug.h"
#include "debugfs.h"

static struct timeval start_time;
static char *host_name;
char *line_ptr = NULL;

const char *fs_compile_out_param[] = {
	SYS_LOG,
	SYS_LOG_LEVEL,
	batctl_settings[BATCTL_SETTINGS_BLA].sysfs_name,
	batctl_settings[BATCTL_SETTINGS_DAT].sysfs_name,
	batctl_settings[BATCTL_SETTINGS_NETWORK_CODING].sysfs_name,
	batctl_debug_tables[BATCTL_TABLE_BLA_CLAIMS].debugfs_name,
	batctl_debug_tables[BATCTL_TABLE_BLA_BACKBONES].debugfs_name,
	batctl_debug_tables[BATCTL_TABLE_DAT].debugfs_name,
	batctl_debug_tables[BATCTL_TABLE_NETWORK_CODING_NODES].debugfs_name,
	NULL,
};

void start_timer(void)
{
	gettimeofday(&start_time, NULL);
}

double end_timer(void)
{
	struct timeval end_time, diff;

	gettimeofday(&end_time, NULL);
	diff.tv_sec = end_time.tv_sec - start_time.tv_sec;
	diff.tv_usec = end_time.tv_usec - start_time.tv_usec;

	if (diff.tv_usec < 0) {
		diff.tv_sec--;
		diff.tv_usec += 1000000;
	}

	return (((double)diff.tv_sec * 1000) + ((double)diff.tv_usec / 1000));
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

static void file_open_problem_dbg(const char *dir, const char *fname,
				  const char *full_path)
{
	const char **ptr;
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

	if (!file_exists(dir)) {
		fprintf(stderr, "Error - mesh has not been enabled yet\n");
		fprintf(stderr, "Activate your mesh by adding interfaces to batman-adv\n");
		return;
	}

	for (ptr = fs_compile_out_param; *ptr; ptr++) {
		if (strcmp(*ptr, fname) != 0)
			continue;

		break;
	}

	fprintf(stderr, "Error - can't open file '%s': %s\n", full_path, strerror(errno));
	if (*ptr) {
		fprintf(stderr, "The option you called seems not to be compiled into your batman-adv kernel module.\n");
		fprintf(stderr, "Consult the README if you wish to learn more about compiling options into batman-adv.\n");
	}
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

	strncpy(full_path, dir, strlen(dir));
	full_path[strlen(dir)] = '\0';
	strncat(full_path, fname, sizeof(full_path) - strlen(full_path) - 1);

open:
	line = 0;
	fp = fopen(full_path, "r");

	if (!fp) {
		if (!(read_opt & SILENCE_ERRORS))
			file_open_problem_dbg(dir, fname, full_path);

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
	int fd = 0, res = EXIT_FAILURE;
	char full_path[500];
	ssize_t write_len;

	strncpy(full_path, dir, strlen(dir));
	full_path[strlen(dir)] = '\0';
	strncat(full_path, fname, sizeof(full_path) - strlen(full_path) - 1);

	fd = open(full_path, O_WRONLY);

	if (fd < 0) {
		file_open_problem_dbg(dir, fname, full_path);
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
	if (fd)
		close(fd);
	return res;
}

struct ether_addr *translate_mac(char *mesh_iface, struct ether_addr *mac)
{
	enum {
		tg_start,
		tg_mac,
		tg_via,
		tg_originator,
	} pos;
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;
	static struct ether_addr in_mac;
	struct ether_addr *mac_result, *mac_tmp;
	FILE *f = NULL;
	size_t len = 0;
	char *line = NULL;
	char *input, *saveptr, *token;
	int line_invalid;

	memcpy(&in_mac, mac, sizeof(in_mac));
	mac_result = &in_mac;

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt)
		goto out;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_TRANSTABLE_GLOBAL, mesh_iface, full_path, sizeof(full_path));

	f = fopen(full_path, "r");
	if (!f)
		goto out;

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
				if (!mac_tmp || memcmp(mac_tmp, &in_mac,
						       sizeof(in_mac)) != 0)
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
					mac_result = mac_tmp;
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
	return mac_result;
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

/**
 * rtnl_open - open a socket to rtnl and send a request
 * @nh: the header of the request to send
 * @protocol: the protocol to use when opening the socket
 *
 * Return 0 on success or a negative error code otherwise
 */
static int rtnl_open(void *req, int protocol)
{
	static uint32_t nr_call = 0;
	uint32_t pid = (++nr_call + getpid()) & 0x3FFFFF;
	struct sockaddr_nl addrnl;
	struct nlmsghdr *nh;
	int socknl;
	int ret;

	memset(&addrnl, 0, sizeof(addrnl));
	addrnl.nl_family = AF_NETLINK;
	addrnl.nl_pid = pid;
	addrnl.nl_groups = 0;

	socknl = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (socknl < 0)
		goto out;

	ret = bind(socknl, (struct sockaddr*)&addrnl, sizeof(addrnl));
	if (ret < 0)
		goto outclose;

	/* the nlmsghdr object must always be the first member in the req
	 * structure
	 */
	nh = (struct nlmsghdr *)req;

	ret = send(socknl, nh, nh->nlmsg_len, 0);
	if (ret < 0)
		goto outclose;
out:
	return socknl;
outclose:
	close(socknl);
	return ret;
}

static int resolve_mac_from_cache_open(int ai_family)
{
	struct {
		struct nlmsghdr hdr;
		struct ndmsg msg;
	} nlreq;

	memset(&nlreq, 0, sizeof(nlreq));
	nlreq.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(nlreq.msg));
	nlreq.hdr.nlmsg_type = RTM_GETNEIGH;
	nlreq.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlreq.msg.ndm_family = ai_family;

	return rtnl_open(&nlreq, NETLINK_ROUTE);
}

static ssize_t resolve_mac_from_cache_dump(int sock, void **buf, size_t *buflen)
{
	struct iovec iov;
	struct msghdr msg;
	ssize_t ret = -1;
	int flags = MSG_PEEK | MSG_TRUNC;

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = 0;
	msg.msg_control = NULL;
	msg.msg_flags = 0;

	iov.iov_len = *buflen;
	iov.iov_base = *buf;

	ret = recvmsg(sock, &msg, flags);
	if (ret < 0)
		goto err;

	if (msg.msg_flags & MSG_TRUNC) {
		if ((size_t)ret <= *buflen) {
			ret = -ENOBUFS;
			goto err;
		}

		while (*buflen <= (size_t)ret) {
			if (*buflen == 0)
				*buflen = 1;
			*buflen *= 2;
		}

		*buf = realloc(*buf, *buflen);
		if (!*buf) {
			ret = -ENOMEM;
			*buflen = 0;
			goto err;
		}
	}
	flags = 0;

	ret = recvmsg(sock, &msg, flags);
	if (ret < 0)
		goto err;

	return ret;
err:
	free(*buf);
	*buf = NULL;
	return ret;
}

static int resolve_mac_from_cache_parse(struct ndmsg *ndmsg, size_t len_payload,
					struct ether_addr *mac_addr,
					uint8_t *l3addr,
					size_t l3_len)
{
	int l3found, llfound;
	struct rtattr *rtattr;
	struct ether_addr mac_empty;

	l3found = 0;
	llfound = 0;
	memset(&mac_empty, 0, sizeof(mac_empty));

	for (rtattr = RTM_RTA(ndmsg); RTA_OK(rtattr, len_payload);
		rtattr = RTA_NEXT(rtattr, len_payload)) {
		switch (rtattr->rta_type) {
		case NDA_DST:
			memcpy(l3addr, RTA_DATA(rtattr), l3_len);
			l3found = 1;
			break;
		case NDA_LLADDR:
			memcpy(mac_addr, RTA_DATA(rtattr), ETH_ALEN);
			if (memcmp(mac_addr, &mac_empty,
					sizeof(mac_empty)) == 0)
				llfound = 0;
			else
				llfound = 1;
			break;
		}
	}

	return l3found && llfound;
}

static struct ether_addr *resolve_mac_from_cache(int ai_family,
						 const void *l3addr)
{
	uint8_t l3addr_tmp[16];
	static struct ether_addr mac_tmp;
	struct ether_addr *mac_result = NULL;
	void *buf = NULL;
	size_t buflen;
	struct nlmsghdr *nh;
	ssize_t len;
	size_t l3_len, mlen;
	int socknl;
	int parsed;
	int finished = 0;

	switch (ai_family) {
	case AF_INET:
		l3_len = 4;
		break;
	case AF_INET6:
		l3_len = 16;
		break;
	default:
		l3_len = 0;
	}

	buflen = 8192;
	buf = malloc(buflen);
	if (!buf)
		goto err;

	socknl = resolve_mac_from_cache_open(ai_family);
	if (socknl < 0)
		goto err;


	while (!finished) {
		len = resolve_mac_from_cache_dump(socknl, &buf, &buflen);
		if (len < 0)
			goto err_sock;
		mlen = len;

		for (nh = buf; NLMSG_OK(nh, mlen); nh = NLMSG_NEXT(nh, mlen)) {
			if (nh->nlmsg_type == NLMSG_DONE) {
				finished = 1;
				break;
			}

			parsed = resolve_mac_from_cache_parse(NLMSG_DATA(nh),
							      RTM_PAYLOAD(nh),
							      &mac_tmp,
							      l3addr_tmp,
							      l3_len);
			if (parsed) {
				if (memcmp(&l3addr_tmp, l3addr, l3_len) == 0) {
					mac_result = &mac_tmp;
					finished = 1;
					break;
				}
			}
		}
	}

err_sock:
	close(socknl);
err:
	free(buf);
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

/**
 * vlan_get_link_parse - parse a get_link rtnl message and extract the important
 *  data
 * @nh: the reply header
 * @iface: pointer to the buffer where the link interface has to be stored (it
 *  is allocated by this function)
 *
 * Return the vid in case of success or -1 otherwise
 */
static int vlan_get_link_parse(struct nlmsghdr *nh, char **iface)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	size_t vlan_len, info_len, len = nh->nlmsg_len;
	struct rtattr *rta, *info, *vlan;
	int idx = -1, vid = -1;

	*iface = NULL;

	rta = IFLA_RTA(ifi);
	while (RTA_OK(rta, len)) {
		/* check if the interface is a vlan */
		if (rta->rta_type == IFLA_LINKINFO) {
			info = RTA_DATA(rta);
			info_len = RTA_PAYLOAD(rta);

			while (RTA_OK(info, info_len)) {
				if (info->rta_type == IFLA_INFO_KIND &&
				    strcmp(RTA_DATA(info), "vlan"))
					goto err;

				if (info->rta_type == IFLA_INFO_DATA) {
					vlan = RTA_DATA(info);
					vlan_len = RTA_PAYLOAD(info);

					while (RTA_OK(vlan, vlan_len)) {
						if (vlan->rta_type == IFLA_VLAN_ID)
							vid = *(int *)RTA_DATA(vlan);
						vlan = RTA_NEXT(vlan, vlan_len);
					}
				}
				info = RTA_NEXT(info, info_len);
			}
		}

		/* extract the name of the "link" interface */
		if (rta->rta_type == IFLA_LINK) {
			idx = *(int *)RTA_DATA(rta);

			*iface = malloc(IFNAMSIZ + 1);
			if (!if_indextoname(idx, *iface))
				goto err;
		}
		rta = RTA_NEXT(rta, len);
	}

	if (vid == -1)
		goto err;

	if (idx <= 0)
		goto err;

	return vid;
err:
	free(*iface);
	return -1;
}

/**
 * vlan_get_link_dump - receive and dump a get_link rtnl reply
 * @sock: the socket to listen for the reply on
 * @buf: buffer where the reply has to be dumped to
 * @buflen: length of the buffer
 *
 * Returns the amount of dumped bytes
 */
static ssize_t vlan_get_link_dump(int sock, void *buf, size_t buflen)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = 0;
	msg.msg_control = NULL;
	msg.msg_flags = 0;
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);

	iov.iov_len = buflen;
	iov.iov_base = buf;

	return recvmsg(sock, &msg, 0);
}

/**
 * vlan_get_link_open - send a get_link request
 * @ifname: the interface to query
 *
 * Returns 0 in case of success or a negative error code otherwise
 */
static int vlan_get_link_open(const char *ifname)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg ifi;
	} nlreq;

	memset(&nlreq, 0, sizeof(nlreq));
	nlreq.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(nlreq.ifi));
	nlreq.hdr.nlmsg_type = RTM_GETLINK;
	nlreq.hdr.nlmsg_flags = NLM_F_REQUEST;
	nlreq.ifi.ifi_family = AF_UNSPEC;
	nlreq.ifi.ifi_index = if_nametoindex(ifname);

	return rtnl_open(&nlreq, 0);
}

/**
 * vlan_get_link - convert a VLAN interface into its parent one
 * @ifname: the interface to convert
 * @parent: buffer where the parent interface name will be written (allocated by
 *  this function)
 *
 * Returns the vlan identifier on success or -1 on error
 */
int vlan_get_link(const char *ifname, char **parent)
{
	int vid = -1, socknl;
	void *buf = NULL;
	size_t buflen;
	ssize_t len;

	buflen = 8192;
	buf = malloc(buflen);
	if (!buf)
		goto err;

	socknl = vlan_get_link_open(ifname);
	if (socknl < 0)
		goto err;

	len = vlan_get_link_dump(socknl, buf, buflen);
	if (len < 0)
		goto err_sock;

	vid = vlan_get_link_parse(buf, parent);

err_sock:
	close(socknl);
err:
	free(buf);
	return vid;
}
