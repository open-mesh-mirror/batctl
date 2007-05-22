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
	printf("Usage: battool modus [options] destination\n");
	printf("modus: ping\n");
	printf("Use \"battool modus -h\" for available options\n");
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

	if( argc < 3 ) {
		usage();
	}
	
	signal( SIGINT, handler );
	signal( SIGTERM, handler );

	if( strcmp(argv[1], "ping") == 0 ) {
		/* call ping main function */
		return ( ping_main( argc-1, argv+1 ) );

	} else {

		usage();

	}


	exit(EXIT_SUCCESS);
}
