// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <marek.lindner@mailbox.org>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>
#include <netinet/ether.h>

#include "bat-hosts.h"
#include "hash.h"
#include "functions.h"

static struct hashtable_t *host_hash;
const char *bat_hosts_path[3] = {"/etc/bat-hosts", "~/bat-hosts", "bat-hosts"};

static int compare_mac(void *data1, void *data2)
{
	return (memcmp(data1, data2, sizeof(struct ether_addr)) == 0 ? 1 : 0);
}

static int choose_mac(void *data, int32_t size)
{
	uint32_t m_size = sizeof(struct ether_addr);
	unsigned char *key = data;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < m_size; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (hash % size);
}

static void parse_hosts_file(struct hashtable_t **hash, const char path[], int read_opt)
{
	struct hashtable_t *swaphash;
	char name[HOST_NAME_MAX_LEN];
	struct ether_addr *mac_addr;
	struct bat_host *bat_host;
	char *line_ptr = NULL;
	char mac_str[18];
	size_t len = 0;
	FILE *fd;

	name[0] = '\0';
	mac_str[0] = '\0';

	fd = fopen(path, "r");
	if (!fd)
		return;

	while (getline(&line_ptr, &len, fd) != -1) {
		/* ignore empty lines and comments */
		if ((line_ptr[0] == '\n') || (line_ptr[0] == '#'))
			continue;

		if (sscanf(line_ptr, "%17[^ \t]%49s\n", mac_str, name) != 2) {
			if (read_opt & USE_BAT_HOSTS)
				fprintf(stderr,
					"Warning - unrecognized bat-host definition: %s",
					line_ptr);
			continue;
		}

		mac_addr = ether_aton(mac_str);
		if (!mac_addr) {
			if (read_opt & USE_BAT_HOSTS)
				fprintf(stderr,
					"Warning - invalid mac address in '%s' detected: %s\n",
					path, mac_str);
			continue;
		}

		bat_host = bat_hosts_find_by_mac((char *)mac_addr);

		/* mac entry already exists - we found a new name for it */
		if (bat_host) {
			/* if the mac addresses and the names are the same we
			 * can safely ignore the entry
			 */
			if (strcmp(bat_host->name, name) == 0)
				continue;

			if (read_opt & USE_BAT_HOSTS)
				fprintf(stderr,
					"Warning - mac already known (changing name from '%s' to '%s'): %s\n",
					bat_host->name, name, mac_str);
			strncpy(bat_host->name, name, HOST_NAME_MAX_LEN);
			bat_host->name[HOST_NAME_MAX_LEN - 1] = '\0';
			continue;
		}

		bat_host = bat_hosts_find_by_name(name);

		/* name entry already exists - we found a new mac address for it */
		if (bat_host) {
			if (read_opt & USE_BAT_HOSTS)
				fprintf(stderr,
					"Warning - name already known (changing mac from '%s' to '%s'): %s\n",
					ether_ntoa(&bat_host->mac_addr), mac_str, name);
			hash_remove(*hash, bat_host);
			free(bat_host);
		}

		bat_host = malloc(sizeof(struct bat_host));

		if (!bat_host) {
			if (read_opt & USE_BAT_HOSTS)
				perror("Error - could not allocate memory");
			goto out;
		}

		memcpy(&bat_host->mac_addr, mac_addr, sizeof(struct ether_addr));
		strncpy(bat_host->name, name, HOST_NAME_MAX_LEN);
		bat_host->name[HOST_NAME_MAX_LEN - 1] = '\0';

		hash_add(*hash, bat_host);

		if ((*hash)->elements * 4 > (*hash)->size) {
			swaphash = hash_resize((*hash), (*hash)->size * 2);

			if (swaphash)
				*hash = swaphash;
			else if (read_opt & USE_BAT_HOSTS)
				fprintf(stderr, "Warning - couldn't resize bat hosts hash table\n");
		}
	}

out:
	if (fd)
		fclose(fd);
	if (line_ptr)
		free(line_ptr);
}

void bat_hosts_init(int read_opt)
{
	size_t locations = sizeof(bat_hosts_path) / sizeof(char *);
	char confdir[CONF_DIR_LEN];
	unsigned int parse;
	char *normalized;
	unsigned int i;
	unsigned int j;
	char *homedir;

	/***
	 * realpath could allocate the memory for us but some embedded libc
	 * implementations seem to expect a buffer as second argument
	 */
	normalized = malloc(locations * PATH_MAX);
	if (!normalized) {
		if (read_opt & USE_BAT_HOSTS)
			printf("Warning - could not get memory for bat-hosts file parsing\n");
		return;
	}

	memset(normalized, 0, locations * PATH_MAX);
	host_hash = hash_new(64, compare_mac, choose_mac);

	if (!host_hash) {
		if (read_opt & USE_BAT_HOSTS)
			printf("Warning - could not create bat hosts hash table\n");
		goto out;
	}

	homedir = getenv("HOME");

	for (i = 0; i < locations; i++) {
		strcpy(confdir, "");

		if (strlen(bat_hosts_path[i]) >= 2 &&
		    bat_hosts_path[i][0] == '~' && bat_hosts_path[i][1] == '/') {
			if (!homedir)
				continue;

			snprintf(confdir, CONF_DIR_LEN, "%s%s", homedir, &bat_hosts_path[i][1]);
		} else {
			strncpy(confdir, bat_hosts_path[i], CONF_DIR_LEN);
			confdir[CONF_DIR_LEN - 1] = '\0';
		}

		if (!realpath(confdir, normalized + (i * PATH_MAX)))
			continue;

		/* check for duplicates: don't parse the same file twice */
		parse = 1;
		for (j = 0; j < i; j++) {
			if (strncmp(normalized + (i * PATH_MAX),
				    normalized + (j * PATH_MAX),
				    CONF_DIR_LEN) == 0) {
				parse = 0;
				break;
			}
		}

		if (parse)
			parse_hosts_file(&host_hash, normalized + (i * PATH_MAX), read_opt);
	}

out:
	free(normalized);
}

struct bat_host *bat_hosts_find_by_name(char *name)
{
	struct bat_host *bat_host = NULL;
	struct hash_it_t *hashit = NULL;
	struct bat_host *tmp_bat_host;

	if (!host_hash)
		return NULL;

	while (NULL != (hashit = hash_iterate(host_hash, hashit))) {
		tmp_bat_host = (struct bat_host *)hashit->bucket->data;

		if (strncmp(tmp_bat_host->name, name, HOST_NAME_MAX_LEN - 1) == 0)
			bat_host = tmp_bat_host;
	}

	return bat_host;
}

struct bat_host *bat_hosts_find_by_mac(char *mac)
{
	if (!host_hash)
		return NULL;

	return (struct bat_host *)hash_find(host_hash, mac);
}

static void bat_host_free(void *data)
{
	free(data);
}

void bat_hosts_free(void)
{
	if (host_hash)
		hash_delete(host_hash, bat_host_free);
}
