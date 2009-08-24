/* Copyright (C) 2009 B.A.T.M.A.N. contributors:
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
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "main.h"
#include "bisect.h"
#include "bat-hosts.h"
#include "hash.h"
#include "functions.h"

static struct hashtable_t *node_hash = NULL;
static struct bat_node *curr_bat_node = NULL;

static void bisect_usage(void)
{
	printf("Usage: batctl bisect [options] <file1> <file2> .. <fileN>\n");
	printf("options:\n");
	printf(" \t -h print this help\n");
	printf(" \t -n don't convert addresses to bat-host names\n");
}

static int compare_mac(void *data1, void *data2)
{
	return (memcmp(data1, data2, NAME_LEN - 1) == 0 ? 1 : 0);
}

static int choose_mac(void *data, int32_t size)
{
	unsigned char *key= data;
	uint32_t hash = 0, m_size = NAME_LEN - 1;
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

static int compare_name(void *data1, void *data2)
{
	return (memcmp(data1, data2, NAME_LEN) == 0 ? 1 : 0);
}

static struct bat_node *node_get(char *name)
{
	struct bat_node *bat_node;

	bat_node = (struct bat_node *)hash_find(node_hash, name);
	if (bat_node)
		goto out;

	bat_node = malloc(sizeof(struct bat_node));
	if (!bat_node) {
		fprintf(stderr, "Could not allocate memory for data structure (out of mem?) - skipping");
		return NULL;
	}

	strncpy(bat_node->name, name, NAME_LEN);
	INIT_LIST_HEAD_FIRST(bat_node->event_list);
	INIT_LIST_HEAD_FIRST(bat_node->rt_table_list);
	memset(bat_node->loop_magic, 0, sizeof(bat_node->loop_magic));
	hash_add(node_hash, bat_node);

out:
	return bat_node;
}

static void node_free(void *data)
{
	struct seqno_event *seqno_event, *seqno_event_tmp;
	struct rt_table *rt_table, *rt_table_tmp;
	struct bat_node *bat_node = (struct bat_node *)data;

	list_for_each_entry_safe(seqno_event, seqno_event_tmp, &bat_node->event_list, list) {
		list_del((struct list_head *)&bat_node->event_list, &seqno_event->list, &bat_node->event_list);
		free(seqno_event);
	}

	list_for_each_entry_safe(rt_table, rt_table_tmp, &bat_node->rt_table_list, list) {
		list_del((struct list_head *)&bat_node->rt_table_list, &rt_table->list, &bat_node->rt_table_list);
		free(rt_table);
	}

	free(bat_node);
}

static int routing_table_new(char *orig, char *next_hop, char *old_next_hop)
{
	struct bat_node *next_hop_node;
	struct rt_table *rt_table, *prev_rt_table;
	int i;

	if (!curr_bat_node) {
		fprintf(stderr, "Routing table change without preceeding OGM - skipping");
		goto err;
	}

	if (!orig) {
		fprintf(stderr, "Invalid originator found - skipping");
		goto err;
	}

	if (!next_hop) {
		fprintf(stderr, "Invalid next hop found - skipping");
		goto err;
	}

	if (!old_next_hop) {
		fprintf(stderr, "Invalid old next hop found - skipping");
		goto err;
	}

	next_hop_node = node_get(next_hop);
	if (!next_hop_node)
		goto err;

	rt_table = malloc(sizeof(struct rt_table));
	if (!rt_table) {
		fprintf(stderr, "Could not allocate memory for routing table (out of mem?) - skipping");
		goto err;
	}

	INIT_LIST_HEAD(&rt_table->list);
	rt_table->num_entries = 1;

	if (!(list_empty(&curr_bat_node->rt_table_list))) {
		prev_rt_table = (struct rt_table *)(curr_bat_node->rt_table_list.prev);
		rt_table->num_entries = prev_rt_table->num_entries + 1;

		/* if we had a route already we just change the entry */
		for (i = 0; i < prev_rt_table->num_entries; i++) {
			if (compare_name(orig, prev_rt_table->entries[i].orig)) {
				rt_table->num_entries--;
				break;
			}
		}
	}

	rt_table->entries = malloc(sizeof(struct rt_entry) * rt_table->num_entries);
	if (!rt_table->entries) {
		fprintf(stderr, "Could not allocate memory for routing table entries (out of mem?) - skipping");
		goto table_free;
	}

	if (!(list_empty(&curr_bat_node->rt_table_list)))
		memcpy(rt_table->entries, prev_rt_table->entries, prev_rt_table->num_entries * sizeof(struct rt_entry));

	if ((rt_table->num_entries == 1) ||
	    (rt_table->num_entries != prev_rt_table->num_entries)) {
		i = rt_table->num_entries;
		strncpy(rt_table->entries[i - 1].orig, orig, NAME_LEN);
		rt_table->entries[i - 1].next_hop = next_hop_node;
	} else {

		rt_table->entries[i].next_hop = next_hop_node;

	}

	list_add_tail(&rt_table->list, &curr_bat_node->rt_table_list);
	((struct seqno_event *)(curr_bat_node->event_list.prev))->rt_table = rt_table;

	return 1;

table_free:
	free(rt_table);
err:
	return 0;
}

static int seqno_event_new(char *iface_addr, char *orig, char *neigh, int seqno, int tq)
{
	struct bat_node *orig_node, *neigh_node;
	struct seqno_event *seqno_event;

	if (!iface_addr) {
		fprintf(stderr, "Invalid interface address found - skipping");
		goto err;
	}

	if (!orig) {
		fprintf(stderr, "Invalid originator found - skipping");
		goto err;
	}

	if (!neigh) {
		fprintf(stderr, "Invalid neighbor found - skipping");
		goto err;
	}

	if ((seqno < 0) || (seqno > 65535)) {
		fprintf(stderr, "Invalid sequence number found (%i) - skipping", seqno);
		goto err;
	}

	if ((tq < 0) || (tq > 255)) {
		fprintf(stderr, "Invalid tq value found (%i) - skipping", tq);
		goto err;
	}

	curr_bat_node = node_get(iface_addr);
	if (!curr_bat_node)
		goto err;

	orig_node = node_get(orig);
	if (!orig_node)
		goto err;

	neigh_node = node_get(neigh);
	if (!neigh_node)
		goto err;

	seqno_event = malloc(sizeof(struct seqno_event));
	if (!seqno_event) {
		fprintf(stderr, "Could not allocate memory for seqno event (out of mem?) - skipping");
		goto err;
	}

	INIT_LIST_HEAD(&seqno_event->list);
	seqno_event->orig = orig_node;
	seqno_event->neigh = neigh_node;
	seqno_event->seqno = seqno;
	seqno_event->tq = tq;
	seqno_event->rt_table = NULL;
	list_add_tail(&seqno_event->list, &curr_bat_node->event_list);

	return 1;

err:
	return 0;
}

static int parse_log_file(char *file_path)
{
	FILE *fd;
	char line_buff[256], *start_ptr, *tok_ptr;
	char *neigh, *iface_addr, *orig, *old_orig;
	int line_count = 0, tq, seqno, i, res;

	fd = fopen(file_path, "r");

	if (!fd) {
		fprintf(stderr, "Error - could not open file '%s': %s\n", file_path, strerror(errno));
		return 0;
	}

	while (fgets(line_buff, sizeof(line_buff), fd) != NULL) {
		/* ignore the timestamp at the beginning of each line */
		start_ptr = line_buff + 13;
		line_count++;

		if (strstr(start_ptr, "Received BATMAN packet via NB")) {
			tok_ptr = strtok(start_ptr, " ");
			neigh = iface_addr = orig = NULL;
			seqno = tq = -1;

			for (i = 0; i < 20; i++) {
				tok_ptr = strtok(NULL, " ");
				if (!tok_ptr)
					break;

				switch (i) {
				case 4:
					neigh = tok_ptr;
					neigh[strlen(neigh) - 1] = 0;
					break;
				case 7:
					iface_addr = tok_ptr + 1;
					iface_addr[strlen(iface_addr) - 1] = 0;
					break;
				case 10:
					orig = tok_ptr;
					orig[strlen(orig) - 1] = 0;
					break;
				case 16:
					seqno = strtol(tok_ptr, NULL, 10);
					break;
				case 18:
					tq = strtol(tok_ptr, NULL, 10);
					break;
				}
			}

			if (tq ==  -1) {
				fprintf(stderr, "Broken 'received packet' line found - skipping [file: %s, line: %i]\n", file_path, line_count);
				continue;
			}

// 			fprintf(stderr, "received packet  (line %i): neigh: '%s', iface_addr: '%s', orig: '%s', seqno: %i, tq: %i\n", line_count, neigh, iface_addr, orig, seqno, tq);

			res = seqno_event_new(iface_addr, orig, neigh, seqno, tq);
			if (res < 1)
				fprintf(stderr, " [file: %s, line: %i]\n", file_path, line_count);

		} else if (strstr(start_ptr, "Changing route towards")) {
			tok_ptr = strtok(start_ptr, " ");
			orig = neigh = old_orig = NULL;

			for (i = 0; i < 12; i++) {
				tok_ptr = strtok(NULL, " ");
				if (!tok_ptr)
					break;

				switch (i) {
				case 2:
					orig = tok_ptr;
					break;
				case 5:
					neigh = tok_ptr;
					break;
				case 9:
					old_orig = tok_ptr;
					old_orig[strlen(old_orig) - 2] = 0;
					break;
				}
			}

			if (!old_orig) {
				fprintf(stderr, "Broken 'changing route' line found - skipping [file: %s, line: %i]\n", file_path, line_count);
				continue;
			}

// 			printf("changing route (line %i): orig: '%s', neigh: '%s', old_orig: '%s'\n", line_count, orig, neigh, old_orig);

			res = routing_table_new(orig, neigh, old_orig);
			if (res < 1)
				fprintf(stderr, " [file: %s, line: %i]\n", file_path, line_count);
		}
	}

	printf("File '%s' parsed (lines: %i)\n", file_path, line_count);
	fclose(fd);
	return 1;
}

int validate_path(struct bat_node *bat_node, struct seqno_event *seqno_event, struct rt_entry *rt_entry)
{
	struct bat_node *next_hop_node;
	struct seqno_event *seqno_event_tmp;
	struct rt_table *rt_table_tmp;
	struct rt_entry *rt_entry_tmp = rt_entry;
	char curr_loop_magic[LOOP_MAGIC_LEN];
	int i;

	snprintf(curr_loop_magic, LOOP_MAGIC_LEN, "%s%s%i", bat_node->name, rt_entry->orig, seqno_event->seqno);

	printf("Path towards %s (seqno %i):", rt_entry->orig, seqno_event->seqno);

	/* single hop neighbors won't enter the while loop */
	if (compare_name(rt_entry->orig, rt_entry_tmp->next_hop->name))
		printf(" * %s", rt_entry_tmp->next_hop->name);

	while (!compare_name(rt_entry->orig, rt_entry_tmp->next_hop->name)) {
		next_hop_node = rt_entry_tmp->next_hop;

		printf(" * %s", next_hop_node->name);

		/* no more data - path seems[tm] fine */
		if (list_empty(&next_hop_node->event_list))
			goto out;

		/* same here */
		if (list_empty(&next_hop_node->rt_table_list))
			continue;

		rt_table_tmp = NULL;
		rt_entry_tmp = NULL;

		/* we are running in a loop */
		if (memcmp(curr_loop_magic, next_hop_node->loop_magic, LOOP_MAGIC_LEN) == 0) {
			printf(" -> aborted due to loop");
			goto out;
		}

		memcpy(next_hop_node->loop_magic, curr_loop_magic, sizeof(next_hop_node->loop_magic));

		list_for_each_entry(seqno_event_tmp, &next_hop_node->event_list, list) {
			if (seqno_event_tmp->rt_table)
				rt_table_tmp = seqno_event_tmp->rt_table;

			if ((seqno_event_tmp->seqno == seqno_event->seqno) &&
			    (seqno_event_tmp->orig == seqno_event->orig))
				break;
		}

		/* no routing data so far - what can we do ? */
		if (!rt_table_tmp)
			goto out;

		/* search the following next hop */
		for (i = 0; i < rt_table_tmp->num_entries; i++) {
			if (compare_name(rt_table_tmp->entries[i].orig, rt_entry->orig)) {
				rt_entry_tmp = (struct rt_entry *)&rt_table_tmp->entries[i];
				break;
			}
		}

		/* no routing entry of orig ?? */
		if (!rt_entry_tmp)
			goto out;
	}

out:
	printf("\n");
	return 1;
}

void validate_rt_tables(void)
{
	struct bat_node *bat_node;
	struct seqno_event *seqno_event;
	struct hash_it_t *hashit = NULL;
	int i;

	printf("\nAnalyzing routing tables:\n");

	while (NULL != (hashit = hash_iterate(node_hash, hashit))) {
		bat_node = hashit->bucket->data;

		/* we might have no log file from this node */
		if (list_empty(&bat_node->event_list)) {
			printf("No seqno data from node '%s' - skipping\n", bat_node->name);
			continue;
		}

		/* or routing tables */
		if (list_empty(&bat_node->rt_table_list)) {
			printf("No routing tables from node '%s' - skipping\n", bat_node->name);
			continue;
		}

		printf("Checking host: %s\n", bat_node->name);
		list_for_each_entry(seqno_event, &bat_node->event_list, list) {
			/**
			 * this received packet did not trigger a routing
			 * table change and is considered harmless
			 */
			if (!seqno_event->rt_table)
				continue;

			for (i = 0; i < seqno_event->rt_table->num_entries; i++) {
				validate_path(bat_node, seqno_event, (struct rt_entry *)&seqno_event->rt_table->entries[i]);
			}
		}
	}
}

int bisect(int argc, char **argv)
{
	int ret = EXIT_FAILURE, res, optchar, found_args = 1;
	int read_opt = USE_BAT_HOSTS, num_parsed_files;

	while ((optchar = getopt(argc, argv, "hn")) != -1) {
		switch (optchar) {
		case 'h':
			bisect_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		default:
			bisect_usage();
			return EXIT_FAILURE;
		}
	}

	if (argc <= found_args + 1) {
		printf("Error - need at least 2 log files to compare\n");
		bisect_usage();
		goto err;
	}

	node_hash = hash_new(64, compare_mac, choose_mac);

	if (!node_hash) {
		printf("Error - couldn't not create node hash table\n");
		goto err;
	}

	bat_hosts_init();
	num_parsed_files = 0;

	while (argc > found_args) {
		res = parse_log_file(argv[found_args]);

		if (res > 0)
			num_parsed_files++;

		found_args++;
	}

	if (num_parsed_files < 2) {
		printf("Error - need at least 2 log files to compare\n");
		goto err;
	}

	validate_rt_tables();
	ret = EXIT_SUCCESS;

err:
	if (node_hash)
		hash_delete(node_hash, node_free);
	bat_hosts_free();
	return ret;
}
