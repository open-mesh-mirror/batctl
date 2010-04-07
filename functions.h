/*
 * Copyright (C) 2007-2010 B.A.T.M.A.N. contributors:
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



#include <netinet/if_ether.h>


#define ETH_STR_LEN 17
#define BATMAN_ADV_TAG "batman-adv:"
#define SEARCH_ARGS_TAG "commands:"

/* return time delta from start to end in milliseconds */
void start_timer(void);
double end_timer(void);
char *ether_ntoa_long(const struct ether_addr *addr);
char *get_name_by_macaddr(struct ether_addr *mac_addr, int read_opt);
char *get_name_by_macstr(char *mac_str, int read_opt);
int read_file(char *dir, char *path, int read_opt);
int write_file(char *dir, char *fname, char *arg1, char *arg2);
int check_proc_dir(char *dir);

extern char *line_ptr;

enum {
	SINGLE_READ = 0x00,
	CONT_READ = 0x01,
	CLR_CONT_READ = 0x02,
	USE_BAT_HOSTS = 0x04,
	LOG_MODE = 0x08,
	USE_READ_BUFF = 0x10,
	SEARCH_ARGS = 0x20,
	SILENCE_ERRORS = 0x40,
};
