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

#include "list-batman.h"

#define NAME_LEN 18
#define LOOP_MAGIC_LEN ((2 * NAME_LEN) + (2 * sizeof(int)) - 2)

int bisect(int argc, char **argv);

struct bat_node {
	char name[NAME_LEN];
	struct list_head_first event_list;
	struct list_head_first rt_table_list;
	char loop_magic[LOOP_MAGIC_LEN];
};

struct rt_table {
	struct list_head list;
	int num_entries;
	struct rt_entry *entries;
};

struct rt_entry {
	char orig[NAME_LEN];
	struct bat_node *next_hop;
};

struct seqno_event {
	struct list_head list;
	struct bat_node *orig;
	struct bat_node *neigh;
	int seqno;
	int tq;
	struct rt_table *rt_table;
};
