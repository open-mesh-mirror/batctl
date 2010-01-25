/*
 * Copyright (C) 2007-2009 B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <a.langer@q-dsl.de>, Marek Lindner <lindner_marek@yahoo.de>
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
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "main.h"
#include "bat-hosts.h"
#include "hash.h"


static struct hashtable_t *host_hash = NULL;
const char *bat_hosts_path[3] = {"/etc/bat-hosts", "~/bat-hosts", "bat-hosts"};


static int compare_mac(void *data1, void *data2)
{
	return (memcmp(data1, data2, sizeof(struct ether_addr)) == 0 ? 1 : 0);
}

static int choose_mac(void *data, int32_t size)
{
	unsigned char *key= data;
	uint32_t hash = 0, m_size = sizeof(struct ether_addr);
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

static void parse_hosts_file(struct hashtable_t **hash, const char path[])
{
	FILE *fd;
	char *line_ptr = NULL;
	char name[HOST_NAME_MAX_LEN], mac_str[18];
	struct ether_addr *mac_addr;
	struct bat_host *bat_host;
	struct hashtable_t *swaphash;
	size_t len = 0;

	name[0] = mac_str[0] = '\0';

	fd = fopen(path, "r");
	if (!fd)
		return;

	while (getline(&line_ptr, &len, fd) != -1) {
		/* ignore empty lines and comments */
		if ((line_ptr[0] == '\n') || (line_ptr[0] == '#'))
			continue;

		if (sscanf(line_ptr, "%[^ \t]%s\n", mac_str, name) != 2) {
			fprintf(stderr, "Warning - unrecognized bat-host definition: %s", line_ptr);
			continue;
		}

		mac_addr = ether_aton(mac_str);
		if (!mac_addr) {
			fprintf(stderr, "Warning - invalid mac address in '%s' detected: %s\n", path, mac_str);
			continue;
		}

		bat_host = bat_hosts_find_by_mac((char *)mac_addr);

		/* mac entry already exists - we found a new name for it */
		if (bat_host) {
			fprintf(stderr, "Warning - mac already known (changing name from '%s' to '%s'): %s\n",
					bat_host->name, name, mac_str);
			strncpy(bat_host->name, name, HOST_NAME_MAX_LEN - 1);
			continue;
		}

		bat_host = bat_hosts_find_by_name(name);

		/* name entry already exists - we found a new mac address for it */
		if (bat_host) {
			fprintf(stderr, "Warning - name already known (changing mac from '%s' to '%s'): %s\n",
					ether_ntoa(&bat_host->mac_addr), mac_str, name);
			hash_remove(*hash, bat_host);
			free(bat_host);
		}

		bat_host = malloc(sizeof(struct bat_host));

		if (!bat_host) {
			fprintf(stderr, "Error - could not allocate memory: %s\n", strerror(errno));
			goto out;
		}

		memcpy(&bat_host->mac_addr, mac_addr, sizeof(struct ether_addr));
		strncpy(bat_host->name, name, HOST_NAME_MAX_LEN - 1);

		hash_add(*hash, bat_host);

		if ((*hash)->elements * 4 > (*hash)->size) {
			swaphash = hash_resize((*hash), (*hash)->size * 2);

			if (swaphash == NULL)
				fprintf(stderr, "Warning - couldn't resize bat hosts hash table\n");
			else
				*hash = swaphash;
		}
	}

out:
	if (fd)
		fclose(fd);
	if (line_ptr)
		free(line_ptr);
	return;
}

void bat_hosts_init(void)
{
	unsigned int i;
	char confdir[CONF_DIR_LEN];
	char *homedir;

	host_hash = hash_new(64, compare_mac, choose_mac);

	if (!host_hash) {
		printf("Warning - couldn't not create bat hosts hash table\n");
		return;
	}

	homedir = getenv("HOME");

	for (i = 0; i < sizeof(bat_hosts_path) / sizeof(char *); i++) {
		strcpy(confdir, "");

		if (strlen(bat_hosts_path[i]) >= 2
		    && bat_hosts_path[i][0] == '~' && bat_hosts_path[i][1] == '/') {
			strncpy(confdir, homedir, CONF_DIR_LEN);
			confdir[CONF_DIR_LEN - 1] = '\0';
			strncat(confdir, &bat_hosts_path[i][1], CONF_DIR_LEN - strlen(confdir));
		} else {
			strncpy(confdir, bat_hosts_path[i], CONF_DIR_LEN);
			confdir[CONF_DIR_LEN - 1] = '\0';
		}

		parse_hosts_file(&host_hash, confdir);
	}
}

struct bat_host *bat_hosts_find_by_name(char *name)
{
	struct hash_it_t *hashit = NULL;
	struct bat_host *bat_host = NULL, *tmp_bat_host;

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
