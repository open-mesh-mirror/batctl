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



#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include "main.h"
#include "bat-hosts.h"
#include "hash.h"


struct hashtable_t *host_hash = NULL;


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

static void parse_hosts_file(struct hashtable_t *hash, char path[])
{
	FILE *fd;
	char name[HOST_NAME_MAX_LEN], mac[18];
	struct ether_addr *tmp_mac;
	struct bat_host *bat_host;
	struct hashtable_t *swaphash;

	name[0] = mac[0] = '\0';

	fd = fopen(path, "r");
	if (fd == NULL)
		return;

	while (fscanf(fd,"%[^ \t]%s\n", name, mac) != EOF) {

		tmp_mac = ether_aton(mac);
		if (!tmp_mac) {
			printf("Warning - invalid mac address in '%s' detected: %s\n", path, mac);
			return;
		}

		bat_host = malloc(sizeof(struct bat_host));

		if (!bat_host) {
			printf("Error - could not allocate memory: %s\n", strerror(errno));
			return;
		}

		memcpy(&bat_host->mac, tmp_mac, sizeof(struct ether_addr));
		strncpy(bat_host->name, name, HOST_NAME_MAX_LEN - 1);

		hash_add(hash, bat_host);

		if (hash->elements * 4 > hash->size) {
			swaphash = hash_resize(hash, hash->size * 2);

			if (swaphash == NULL)
				printf("Warning - couldn't resize bat hosts hash table\n");
			else
				hash = swaphash;
		}

	}

	return;
}

int bat_hosts_init(void)
{
	host_hash = hash_new(64, compare_mac, choose_mac);

	if (!host_hash)
		return 0;

	parse_hosts_file(host_hash, HOSTS_FILE);

	return 1;
}

struct bat_host *bat_hosts_find_by_name(char *name)
{
	struct hash_it_t *hashit = NULL;
	struct bat_host *bat_host = NULL, *tmp_bat_host;

	while (NULL != (hashit = hash_iterate(host_hash, hashit))) {
		tmp_bat_host = (struct bat_host *)hashit->bucket->data;

		if (strcmp(tmp_bat_host->name, name) == 0)
			bat_host = tmp_bat_host;
			break;
	}

	return bat_host;
}

struct bat_host *bat_hosts_find_by_mac(char *mac)
{
	return (struct bat_host *)hash_find(host_hash, mac);
}

void bat_hosts_free(void)
{
	if (host_hash)
		hash_destroy(host_hash);
}
