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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "battool.h"

void usage() {
	printf("Usage:\n\tbattool -v\n\tbattool module [options] destination\n");
	printf("module: ping|p traceroute|tr tcpdump|td\n");
	printf("Use \"battool module -h\" for available options\n");
	exit(EXIT_FAILURE);
}

void parse_hosts_file( struct hosts **tmp, char path[] ) {

	FILE *fd;
	char name[50], mac[18];

	name[0] = mac[0] = '\0';

	if( ( fd = fopen(path, "r") ) == NULL )
		return;

	while( fscanf(fd,"%[^ \t]%s\n", name, mac ) != EOF ) {

		if( (*tmp) == NULL ) {
			(*tmp) = malloc( sizeof( struct hosts) );
		}

		if( (*tmp) != NULL ) {
			strncpy( (*tmp)->name, name, 49 );
			strncpy( (*tmp)->mac, mac, 17 );
			(*tmp)->next = NULL;
			tmp = &(*tmp)->next;
		}

	}

	return;

}

int main( int argc, char **argv ) {
	int uid;
	if( strcmp( argv[1], "-v" ) == 0 ) {
		printf("Battool %s\n", VERSION);
		exit(EXIT_SUCCESS);
	}

	if( argc < 3 ) {
		usage();
	}

	uid = getuid();
	if(uid != 0) { printf("You must have UID 0 instead of %d.\n",uid); exit(EXIT_FAILURE); }

	struct hosts *hosts = NULL;
	parse_hosts_file( &hosts,HOSTS_FILE );

	if( strcmp(argv[1], "ping") == 0 || strcmp(argv[1], "p") == 0 ) {
		/* call ping main function */
		return ( ping_main( argc-1, argv+1, hosts ) );

	} else if( strcmp(argv[1], "traceroute") == 0 || strcmp(argv[1], "tr") == 0  ) {
		/* call trace main function */
		return ( traceroute_main( argc-1, argv+1, hosts ) );

	} else if( strcmp(argv[1], "tcpdump") == 0 || strcmp(argv[1], "td") == 0  ) {
		/* call trace main function */
		return ( tcpdump_main( argc-1, argv+1 ) );

	} else {

		usage();

	}


	exit(EXIT_SUCCESS);
}
