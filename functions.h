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



#define ETH_STR_LEN 17

/* return time delta from start to end in milliseconds */
double time_diff(struct timeval *start, struct timeval *end);
int read_proc_file(char *path, int read_opt);
int write_proc_file(char *path, char *value);

enum {
	SINGLE_READ = 0x00,
	CONT_READ = 0x01,
	CLR_CONT_READ = 0x02,
	USE_BAT_HOSTS = 0x04,
};
