/* Copyright (C) 2007 B.A.T.M.A.N. contributors:
 * Andreas Langer <a.langer@q-dsl.de>
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

#include <sys/un.h>
#include "packet.h"

#define UNIX_PATH "/var/run/batmand-adv.socket"

#define SOURCE_VERSION "0.1-alpha"
#define HOSTS_FILE "bat-hosts"

#define find_mac_address(list, tmp , search, target, search_type, target_type ) \
	for( tmp = list; tmp != NULL; tmp = tmp->next ) { \
		if( strcmp( tmp->search_type, search ) == 0 ) { \
			target = tmp->target_type; \
			break; \
		} \
	 }

struct unix_if {
	int32_t unix_sock;
	struct sockaddr_un addr;
};

struct hosts {
	char name[50];
	char mac[18];
	struct hosts *next;
};

int ping_main( int argc, char **argv, struct hosts *hosts );
int traceroute_main( int argc, char **argv, struct hosts *hosts );
