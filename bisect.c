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
	printf(" \t -s seqno range (requires trace seqno node)\n");
	printf(" \t -t trace seqnos of given mac address or bat-host\n");
}

static int compare_name(void *data1, void *data2)
{
	return (memcmp(data1, data2, NAME_LEN) == 0 ? 1 : 0);
}

static int choose_name(void *data, int32_t size)
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

		free(rt_table->entries);
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

static int seqno_event_new(char *iface_addr, char *orig, char *old_orig, char *neigh, int seqno, int tq, int ttl)
{
	struct bat_node *orig_node, *neigh_node, *old_orig_node;
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

	if ((ttl < 0) || (ttl > 255)) {
		fprintf(stderr, "Invalid ttl value found (%i) - skipping", ttl);
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

	old_orig_node = node_get(old_orig);
	if (!old_orig_node)
		goto err;

	seqno_event = malloc(sizeof(struct seqno_event));
	if (!seqno_event) {
		fprintf(stderr, "Could not allocate memory for seqno event (out of mem?) - skipping");
		goto err;
	}

	INIT_LIST_HEAD(&seqno_event->list);
	seqno_event->orig = orig_node;
	seqno_event->neigh = neigh_node;
	seqno_event->old_orig = old_orig_node;
	seqno_event->seqno = seqno;
	seqno_event->tq = tq;
	seqno_event->ttl = ttl;
	seqno_event->rt_table = NULL;
	list_add_tail(&seqno_event->list, &curr_bat_node->event_list);

	return 1;

err:
	return 0;
}

static int parse_log_file(char *file_path)
{
	FILE *fd;
	char line_buff[MAX_LINE], *start_ptr, *tok_ptr;
	char *neigh, *iface_addr, *orig, *old_orig;
	int line_count = 0, tq, ttl, seqno, i, res;

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
			neigh = iface_addr = orig = old_orig = NULL;
			seqno = tq = ttl = -1;

			for (i = 0; i < 21; i++) {
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
				case 14:
					old_orig = tok_ptr;
					old_orig[strlen(old_orig) - 1] = 0;
					break;
				case 16:
					seqno = strtol(tok_ptr, NULL, 10);
					break;
				case 18:
					tq = strtol(tok_ptr, NULL, 10);
					break;
				case 20:
					ttl = strtol(tok_ptr, NULL, 10);
					break;
				}
			}

			if (ttl ==  -1) {
				fprintf(stderr, "Broken 'received packet' line found - skipping [file: %s, line: %i]\n", file_path, line_count);
				continue;
			}

// 			fprintf(stderr, "received packet  (line %i): neigh: '%s', iface_addr: '%s', orig: '%s', old_orig: '%s', seqno: %i, tq: %i, ttl: %i\n", line_count, neigh, iface_addr, orig, old_orig, seqno, tq, ttl);

			res = seqno_event_new(iface_addr, orig, old_orig, neigh, seqno, tq, ttl);
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

// 	printf("File '%s' parsed (lines: %i)\n", file_path, line_count);
	fclose(fd);
	return 1;
}

static int validate_path(struct bat_node *bat_node, struct seqno_event *seqno_event,
                  struct rt_entry *rt_entry, int seqno_count, int read_opt)
{
	struct bat_node *next_hop_node;
	struct seqno_event *seqno_event_tmp;
	struct rt_table *rt_table_tmp;
	struct rt_entry *rt_entry_tmp = rt_entry;
	char curr_loop_magic[LOOP_MAGIC_LEN];
	int i;

	snprintf(curr_loop_magic, LOOP_MAGIC_LEN, "%s%s%i%i",
	         bat_node->name, rt_entry->orig,
	         seqno_event->seqno, seqno_count);

	printf("Path towards %s (seqno %i):",
	       get_name_by_macstr(rt_entry->orig, read_opt),
	       seqno_event->seqno);

	/* single hop neighbors won't enter the while loop */
	if (compare_name(rt_entry->orig, rt_entry_tmp->next_hop->name))
		printf(" * %s",
		       get_name_by_macstr(rt_entry_tmp->next_hop->name, read_opt));

	while (!compare_name(rt_entry->orig, rt_entry_tmp->next_hop->name)) {
		next_hop_node = rt_entry_tmp->next_hop;

		printf(" * %s",
		       get_name_by_macstr(next_hop_node->name, read_opt));

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

static void validate_rt_tables(int read_opt)
{
	struct bat_node *bat_node;
	struct seqno_event *seqno_event;
	struct hash_it_t *hashit = NULL;
	int i, last_seqno = -1, seqno_count = 0;

	printf("\nAnalyzing routing tables:\n");

	while (NULL != (hashit = hash_iterate(node_hash, hashit))) {
		bat_node = hashit->bucket->data;

		/* we might have no log file from this node */
		if (list_empty(&bat_node->event_list)) {
			fprintf(stderr, "No seqno data from node '%s' - skipping\n",
			       get_name_by_macstr(bat_node->name, read_opt));
			continue;
		}

		/* or routing tables */
		if (list_empty(&bat_node->rt_table_list)) {
			fprintf(stderr, "No routing tables from node '%s' - skipping\n",
			       get_name_by_macstr(bat_node->name, read_opt));
			continue;
		}

		printf("Checking host: %s\n",
		       get_name_by_macstr(bat_node->name, read_opt));
		list_for_each_entry(seqno_event, &bat_node->event_list, list) {
			/**
			 * this received packet did not trigger a routing
			 * table change and is considered harmless
			 */
			if (!seqno_event->rt_table)
				continue;

			/**
			 * sometime we change the routing table more than once
			 * with the same seqno
			 */
			if (last_seqno == seqno_event->seqno)
				seqno_count++;
			else
				seqno_count = 0;

			last_seqno = seqno_event->seqno;

			for (i = 0; i < seqno_event->rt_table->num_entries; i++) {
				validate_path(bat_node, seqno_event,
				              (struct rt_entry *)&seqno_event->rt_table->entries[i],
				              seqno_count, read_opt);
			}
		}
	}
}

static void seqno_trace_print_neigh(struct seqno_trace_neigh *seqno_trace_neigh,
			            int num_sisters, char *head, int read_opt)
{
	char new_head[MAX_LINE];
	int i;

	printf("%s%s--- %s [tq: %i, ttl: %i", head,
	               (strlen(head) == 1 ? "" : num_sisters == 0 ? "\\" : "|"),
	               get_name_by_macstr(seqno_trace_neigh->bat_node->name, read_opt),
	               seqno_trace_neigh->seqno_event->tq,
	               seqno_trace_neigh->seqno_event->ttl);

	printf(", neigh: %s", get_name_by_macstr(seqno_trace_neigh->seqno_event->neigh->name, read_opt));
	printf(", old_orig: %s]\n", get_name_by_macstr(seqno_trace_neigh->seqno_event->old_orig->name, read_opt));

	for (i = 0; i < seqno_trace_neigh->num_neighbors; i++) {
		snprintf(new_head, sizeof(new_head), "%s%s",
		         (strlen(head) > 1 ? head : num_sisters == 0 ? " " : head),
		         (strlen(head) == 1 ? " " :
		         num_sisters == 0 ? "  " : "| "));

		seqno_trace_print_neigh(seqno_trace_neigh->seqno_trace_neigh[i],
		                        seqno_trace_neigh->num_neighbors - i - 1, new_head, read_opt);
	}
}

static void seqno_trace_print(struct list_head_first *trace_list, char *trace_orig,
					 int seqno_min, int seqno_max, int read_opt)
{
	struct seqno_trace *seqno_trace;
	char head[MAX_LINE];
	int i;

	printf("Sequence number flow of originator: %s ",
	       get_name_by_macstr(trace_orig, read_opt));

	if ((seqno_min == -1) && (seqno_max == -1))
		printf("[all sequence numbers]\n");
	else if (seqno_min == seqno_max)
		printf("[sequence number: %i]\n", seqno_min);
	else
		printf("[sequence number range: %i-%i]\n", seqno_min, seqno_max);

	list_for_each_entry(seqno_trace, trace_list, list) {
		printf("+=> %s (seqno %i)\n",
		       get_name_by_macstr(trace_orig, read_opt),
		       seqno_trace->seqno);


		for (i = 0; i < seqno_trace->seqno_trace_neigh.num_neighbors; i++) {

			snprintf(head, sizeof(head), "%c",
			         (seqno_trace->seqno_trace_neigh.num_neighbors == i + 1 ? '\\' : '|'));

			seqno_trace_print_neigh(seqno_trace->seqno_trace_neigh.seqno_trace_neigh[i],
			                        seqno_trace->seqno_trace_neigh.num_neighbors - i - 1,
			                        head, read_opt);
		}

		printf("\n");
	}
}

static int _seqno_trace_neigh_add(struct seqno_trace_neigh *seqno_trace_mom,
					struct seqno_trace_neigh *seqno_trace_child)
{
	struct seqno_trace_neigh *data_ptr;

	data_ptr = malloc((seqno_trace_mom->num_neighbors + 1) * sizeof(struct seqno_trace_neigh *));
	if (!data_ptr)
		return 0;

	if (seqno_trace_mom->num_neighbors > 0) {
		memcpy(data_ptr, seqno_trace_mom->seqno_trace_neigh,
		       seqno_trace_mom->num_neighbors * sizeof(struct seqno_trace_neigh *));
		free(seqno_trace_mom->seqno_trace_neigh);
	}

	seqno_trace_mom->num_neighbors++;
	seqno_trace_mom->seqno_trace_neigh = (void *)data_ptr;
	seqno_trace_mom->seqno_trace_neigh[seqno_trace_mom->num_neighbors - 1] = seqno_trace_child;
	return 1;
}

static struct seqno_trace_neigh *seqno_trace_neigh_add(struct seqno_trace_neigh *seqno_trace_neigh,
		                      struct bat_node *bat_node, struct seqno_event *seqno_event)
{
	struct seqno_trace_neigh *seqno_trace_neigh_new;
	int res;

	seqno_trace_neigh_new = malloc(sizeof(struct seqno_trace_neigh));
	if (!seqno_trace_neigh_new)
		goto err;

	seqno_trace_neigh_new->bat_node = bat_node;
	seqno_trace_neigh_new->seqno_event = seqno_event;
	seqno_trace_neigh_new->num_neighbors = 0;

	res = _seqno_trace_neigh_add(seqno_trace_neigh, seqno_trace_neigh_new);

	if (res < 1)
		goto free_neigh;

	return seqno_trace_neigh_new;

free_neigh:
	free(seqno_trace_neigh_new);
err:
	return NULL;
}

static struct seqno_trace_neigh *seqno_trace_find_neigh(struct bat_node *neigh, struct bat_node *old_orig,
				struct seqno_trace_neigh *seqno_trace_neigh)
{
	struct seqno_trace_neigh *seqno_trace_neigh_tmp, *seqno_trace_neigh_ret;
	int i;

	for (i = 0; i < seqno_trace_neigh->num_neighbors; i++) {
		seqno_trace_neigh_tmp = seqno_trace_neigh->seqno_trace_neigh[i];

		if ((neigh == seqno_trace_neigh_tmp->bat_node) &&
		    (old_orig == seqno_trace_neigh_tmp->seqno_event->neigh))
			return seqno_trace_neigh_tmp;

		seqno_trace_neigh_ret = seqno_trace_find_neigh(neigh, old_orig, seqno_trace_neigh_tmp);

		if (seqno_trace_neigh_ret)
			return seqno_trace_neigh_ret;
	}

	return NULL;
}

static void seqno_trace_neigh_free(struct seqno_trace_neigh *seqno_trace_neigh)
{
	int i;

	for (i = 0; i < seqno_trace_neigh->num_neighbors; i++)
		seqno_trace_neigh_free(seqno_trace_neigh->seqno_trace_neigh[i]);

	if (seqno_trace_neigh->num_neighbors > 0)
		free(seqno_trace_neigh->seqno_trace_neigh);

	free(seqno_trace_neigh);
}

static int seqno_trace_fix_leaf(struct seqno_trace_neigh *seqno_trace_mom,
					struct seqno_trace_neigh *seqno_trace_old_mom,
					struct seqno_trace_neigh *seqno_trace_child)
{
	struct seqno_trace_neigh **data_ptr, *seqno_trace_neigh;
	int i, j = 0;

	data_ptr = malloc((seqno_trace_old_mom->num_neighbors - 1) * sizeof(struct seqno_trace_neigh *));
	if (!data_ptr)
		return 0;

	/* copy all children except the child that is going to move */
	for (i = 0; i < seqno_trace_old_mom->num_neighbors; i++) {
		seqno_trace_neigh = seqno_trace_old_mom->seqno_trace_neigh[i];

		if (seqno_trace_neigh != seqno_trace_child) {
			data_ptr[j] = seqno_trace_neigh;
			j++;
		}
	}

	seqno_trace_old_mom->num_neighbors--;
	free(seqno_trace_old_mom->seqno_trace_neigh);
	seqno_trace_old_mom->seqno_trace_neigh = data_ptr;

	return _seqno_trace_neigh_add(seqno_trace_mom, seqno_trace_child);
}

static int seqno_trace_check_leaves(struct seqno_trace *seqno_trace, struct seqno_trace_neigh *seqno_trace_neigh_new)
{
	struct seqno_trace_neigh *seqno_trace_neigh_tmp;
	int i, res;

	for (i = 0; i < seqno_trace->seqno_trace_neigh.num_neighbors; i++) {
		seqno_trace_neigh_tmp = seqno_trace->seqno_trace_neigh.seqno_trace_neigh[i];

		if ((seqno_trace_neigh_tmp->seqno_event->neigh == seqno_trace_neigh_new->bat_node) &&
		    (seqno_trace_neigh_tmp->seqno_event->old_orig == seqno_trace_neigh_new->seqno_event->neigh)) {
			res = seqno_trace_fix_leaf(seqno_trace_neigh_new, &seqno_trace->seqno_trace_neigh, seqno_trace_neigh_tmp);

			if (res < 1)
				return res;

			/* restart checking procedure because we just changed the array we are working on */
			return seqno_trace_check_leaves(seqno_trace, seqno_trace_neigh_new);
		}
	}

	return 1;
}

static struct seqno_trace *seqno_trace_new(struct seqno_event *seqno_event)
{
	struct seqno_trace *seqno_trace;

	seqno_trace = malloc(sizeof(struct seqno_trace));
	if (!seqno_trace) {
		fprintf(stderr, "Could not allocate memory for seqno tracing data (out of mem?)\n");
		return NULL;
	}

	INIT_LIST_HEAD(&seqno_trace->list);
	seqno_trace->seqno = seqno_event->seqno;

	seqno_trace->seqno_trace_neigh.num_neighbors = 0;

	return seqno_trace;
}

static void seqno_trace_free(struct seqno_trace *seqno_trace)
{
	int i;

	for (i = 0; i < seqno_trace->seqno_trace_neigh.num_neighbors; i++)
		seqno_trace_neigh_free(seqno_trace->seqno_trace_neigh.seqno_trace_neigh[i]);

	free(seqno_trace);
}

static int seqno_trace_add(struct list_head_first *trace_list, struct bat_node *bat_node,
		           struct seqno_event *seqno_event)
{
	struct seqno_trace *seqno_trace = NULL, *seqno_trace_tmp = NULL, *seqno_trace_prev = NULL;
	struct seqno_trace_neigh *seqno_trace_neigh;

	list_for_each_entry(seqno_trace_tmp, trace_list, list) {
		if (seqno_trace_tmp->seqno == seqno_event->seqno) {
			seqno_trace = seqno_trace_tmp;
			break;
		}

		if (seqno_trace_tmp->seqno > seqno_event->seqno)
			break;

		seqno_trace_prev = seqno_trace_tmp;
	}

	if (!seqno_trace) {
		seqno_trace = seqno_trace_new(seqno_event);
		if (!seqno_trace)
			goto err;

		if ((list_empty(trace_list)) ||
		    (seqno_event->seqno > ((struct seqno_trace *)trace_list->prev)->seqno))
			list_add_tail(&seqno_trace->list, trace_list);
		else if (seqno_event->seqno < ((struct seqno_trace *)trace_list->next)->seqno)
			list_add_before((struct list_head *)trace_list, trace_list->next, &seqno_trace->list);
		else
			list_add_before(&seqno_trace_prev->list, &seqno_trace_tmp->list, &seqno_trace->list);
	}

	seqno_trace_neigh = seqno_trace_find_neigh(seqno_event->neigh,
				                   seqno_event->old_orig,
				                   &seqno_trace->seqno_trace_neigh);

	/* no neighbor found to hook up to - adding new root node */
	if (!seqno_trace_neigh)
		seqno_trace_neigh = seqno_trace_neigh_add(&seqno_trace->seqno_trace_neigh,
				                          bat_node, seqno_event);
	else
		seqno_trace_neigh = seqno_trace_neigh_add(seqno_trace_neigh, bat_node, seqno_event);

	if (seqno_trace_neigh)
		seqno_trace_check_leaves(seqno_trace, seqno_trace_neigh);

	return 1;

err:
	return 0;
}

static void trace_seqnos(char *trace_orig, int seqno_min, int seqno_max, int read_opt)
{
	struct bat_node *bat_node;
	struct seqno_event *seqno_event;
	struct hash_it_t *hashit = NULL;
	struct list_head_first trace_list;
	struct seqno_trace *seqno_trace, *seqno_trace_tmp;
	int res;

	INIT_LIST_HEAD_FIRST(trace_list);

	while (NULL != (hashit = hash_iterate(node_hash, hashit))) {
		bat_node = hashit->bucket->data;

		/* we might have no log file from this node */
		if (list_empty(&bat_node->event_list))
			continue;

		list_for_each_entry(seqno_event, &bat_node->event_list, list) {
			if (!compare_name(trace_orig, seqno_event->orig->name))
				continue;

			if ((seqno_min != -1) && (seqno_event->seqno < seqno_min))
				continue;

			if ((seqno_max != -1) && (seqno_event->seqno > seqno_max))
				continue;

			res = seqno_trace_add(&trace_list, bat_node, seqno_event);

			if (res < 1)
				goto out;
		}
	}

	seqno_trace_print(&trace_list, trace_orig, seqno_min, seqno_max, read_opt);

out:
	list_for_each_entry_safe(seqno_trace, seqno_trace_tmp, &trace_list, list) {
		list_del((struct list_head *)&trace_list, &seqno_trace->list, &trace_list);
		seqno_trace_free(seqno_trace);
	}

	return;
}

int bisect(int argc, char **argv)
{
	struct bat_host *bat_host;
	struct ether_addr *trace_orig_addr;
	int ret = EXIT_FAILURE, res, optchar, found_args = 1;
	int read_opt = USE_BAT_HOSTS, num_parsed_files;
	int tmp_seqno, seqno_max = -1, seqno_min = -1;
	char *trace_orig_ptr = NULL, trace_orig[NAME_LEN], *dash_ptr;

	while ((optchar = getopt(argc, argv, "hns:t:")) != -1) {
		switch (optchar) {
		case 'h':
			bisect_usage();
			return EXIT_SUCCESS;
		case 'n':
			read_opt &= ~USE_BAT_HOSTS;
			found_args += 1;
			break;
		case 's':
			dash_ptr = strchr(optarg, '-');
			if (dash_ptr)
				*dash_ptr = 0;

			tmp_seqno = strtol(optarg, NULL , 10);
			if ((tmp_seqno >= 0) && (tmp_seqno <= 65535))
				seqno_min = tmp_seqno;
			else
				fprintf(stderr, "Warning - given sequence number is out of range: %i\n", tmp_seqno);

			if (dash_ptr) {
				tmp_seqno = strtol(dash_ptr + 1, NULL , 10);
				if ((tmp_seqno >= 0) && (tmp_seqno <= 65535))
					seqno_max = tmp_seqno;
				else
					fprintf(stderr, "Warning - given sequence number is out of range: %i\n", tmp_seqno);

				*dash_ptr = '-';
			}

			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
			break;
		case 't':
			trace_orig_ptr = optarg;
			found_args += ((*((char*)(optarg - 1)) == optchar ) ? 1 : 2);
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

	node_hash = hash_new(64, compare_name, choose_name);

	if (!node_hash) {
		printf("Error - couldn't not create node hash table\n");
		goto err;
	}

	bat_hosts_init();
	num_parsed_files = 0;

	if (trace_orig_ptr) {
		bat_host = bat_hosts_find_by_name(trace_orig_ptr);

		if (bat_host) {
			trace_orig_ptr = ether_ntoa_long((struct ether_addr *)&bat_host->mac_addr);
			goto copy_name;
		}

		trace_orig_addr = ether_aton(trace_orig_ptr);

		if (!trace_orig_addr) {
			printf("Error - the trace host is not a mac address or bat-host name: %s\n", trace_orig_ptr);
			goto err;
		}

		/**
		 * convert the given mac address to the long format to
		 * make sure we can find it
		 */
		trace_orig_ptr = ether_ntoa_long(trace_orig_addr);

copy_name:
		strncpy(trace_orig, trace_orig_ptr, NAME_LEN);
	}

	if ((seqno_min > 0) && (!trace_orig_ptr)) {
		printf("Error - the sequence range option can't be used without specifying a trace host\n");
		goto err;
	}

	/* we search a specific seqno - no range */
	if ((seqno_min > 0) && (seqno_max == -1))
		seqno_max = seqno_min;

	if (seqno_min > seqno_max) {
		printf("Error - the sequence range minimum (%i) should be smaller than the maximum (%i)\n",
		       seqno_min, seqno_max);
		goto err;
	}

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

	if (trace_orig_ptr)
		trace_seqnos(trace_orig, seqno_min, seqno_max, read_opt);
	else
		validate_rt_tables(read_opt);

	ret = EXIT_SUCCESS;

err:
	if (node_hash)
		hash_delete(node_hash, node_free);
	bat_hosts_free();
	return ret;
}
