/*
 * Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <lindner_marek@yahoo.de>
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
#include <arpa/inet.h>
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

static void file_open_problem_dbg(char *dir, char *fname, char *full_path)
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

int read_file(char *dir, char *fname, int read_opt,
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

int write_file(char *dir, char *fname, char *arg1, char *arg2)
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

static uint32_t resolve_ipv4(const char *asc)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *res;
	struct sockaddr_in *inet4;
	uint32_t addr = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	ret = getaddrinfo(asc, NULL, &hints, &res);
	if (ret)
		return 0;

	if (res) {
		inet4 = (struct sockaddr_in *)res->ai_addr;
		addr = inet4->sin_addr.s_addr;
	}

	freeaddrinfo(res);
	return addr;
}

static void request_arp(uint32_t ipv4_addr)
{
	struct sockaddr_in inet4;
	int sock;
	char t = 0;

	memset(&inet4, 0, sizeof(inet4));
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return;

	inet4.sin_family = AF_INET;
	inet4.sin_port = htons(9);
	inet4.sin_addr.s_addr = ipv4_addr;
	sendto(sock, &t, sizeof(t), 0, (const struct sockaddr *)&inet4,
	       sizeof(inet4));
	close(sock);
}

static struct ether_addr *resolve_mac_from_arp(uint32_t ipv4_addr)
{
	struct ether_addr mac_empty;
	struct ether_addr *mac_result = NULL, *mac_tmp = NULL;
	struct sockaddr_in inet4;
	int ret;
	FILE *f;
	size_t len = 0;
	char *line = NULL;
	int skip_line = 1;
	size_t column;
	char *token, *input, *saveptr;
	int line_invalid;

	memset(&mac_empty, 0, sizeof(mac_empty));

	f = fopen("/proc/net/arp", "r");
	if (!f)
		return NULL;

	while (getline(&line, &len, f) != -1) {
		if (skip_line) {
			skip_line = 0;
			continue;
		}

		line_invalid = 0;
		column = 0;
		input = line;
		while ((token = strtok_r(input, " \t", &saveptr))) {
			input = NULL;

			if (column == 0) {
				ret = inet_pton(AF_INET, token, &inet4.sin_addr);
				if (ret != 1) {
					line_invalid = 1;
					break;
				}
			}

			if (column == 3) {
				mac_tmp = ether_aton(token);
				if (!mac_tmp || memcmp(mac_tmp, &mac_empty,
						       sizeof(mac_empty)) == 0) {
					line_invalid = 1;
					break;
				}
			}

			column++;
		}

		if (column < 4)
			line_invalid = 1;

		if (line_invalid)
			continue;

		if (ipv4_addr == inet4.sin_addr.s_addr) {
			mac_result = mac_tmp;
			break;
		}
	}

	free(line);
	fclose(f);
	return mac_result;
}

static struct ether_addr *resolve_mac_from_ipv4(const char *asc)
{
	uint32_t ipv4_addr;
	int retries = 5;
	struct ether_addr *mac_result = NULL;

	ipv4_addr = resolve_ipv4(asc);
	if (!ipv4_addr)
		return NULL;

	while (retries-- && !mac_result) {
		mac_result = resolve_mac_from_arp(ipv4_addr);
		if (!mac_result) {
			request_arp(ipv4_addr);
			usleep(200000);
		}
	}

	return mac_result;
}

struct ether_addr *resolve_mac(const char *asc)
{
	struct ether_addr *mac_result = NULL;

	mac_result = ether_aton(asc);
	if (mac_result)
		goto out;

	mac_result = resolve_mac_from_ipv4(asc);

out:
	return mac_result;
}
