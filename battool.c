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


uint8_t Stop = 0;

void usage() {
	printf("Usage: battool modus destination\n");
	printf("modus: ping\n");
	printf("destination: 00:0a:00:93:d0:cf can write :a::93:d0:cf\n\n");
	exit(EXIT_FAILURE);
}


void handler( int32_t sig ) {
	switch( sig ) {
		case SIGINT:
		case SIGTERM:
			Stop = 1;
			break;
		default:
			break;
	}
}

int main( int argc, char **argv ) {
	uint8_t mac[6];
	char tmp[2];
	int i,j=0;

	if( argc < 3 ) {
		usage();
	}
	
	
	signal( SIGINT, handler );
	signal( SIGTERM, handler );
	
	if( argc == 3 ) {

		if( strcmp(argv[2], "help") != 0 ) {
			/* convert mac address in int array */
			if( strlen( argv[2] ) > 17 ) {
				printf("The mac address was not correct.\n");
				exit(EXIT_FAILURE);
			}

			for( i = 0; i < strlen( argv[2] ) ; ) {
				if( argv[2][i] != ':' ) {
					tmp[0] = argv[2][i];
				} else {
					mac[j] = 0;
					i++;
					j++;
					continue;
				}

				if( argv[2][i+1] != ':' ) {
					tmp[1] = argv[2][i+1];
					i+=3;
				} else {
					tmp[1] = tmp[0];
					tmp[0] = '0';
					i+=2;
				}

				mac[j] = strtol(tmp,NULL,16);
				j++;
			}

			if( j < 5 || j > 6 ) {
				printf("The mac address was not correct.\n");
				exit(EXIT_FAILURE);
			}

		} else {
			/* print help for modus in argv[1] */
		}

		if( strcmp(argv[1], "ping") == 0 ) {
			/* call ping main function */
			ping_main( mac, argv[2] );

		} else {
			usage();
		}

	} else {
		printf("more options currently not supported\n");
		usage();
		exit(EXIT_FAILURE);
	}


	exit(EXIT_SUCCESS);
}
