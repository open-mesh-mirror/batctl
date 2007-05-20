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

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "battool.h"

void ping_usage() {
	return;
}


void ping_main( uint8_t *mac ) {

	char *send_buff, *rec_buff;
	char begin[] = "p:";
	int sbsize,rbsize;
	int32_t recv_buff_len;
	struct icmp_packet icmp_packet;
	struct unix_if unix_if;
	
	sbsize = sizeof( struct icmp_packet ) + 2;
	rbsize = sizeof( struct icmp_packet );

	unix_if.unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );

	unix_if.addr.sun_family = AF_LOCAL;
	strcpy( unix_if.addr.sun_path, UNIX_PATH );

	
	if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

		printf( "Error - can't connect to unix socket '%s': %s ! Is batmand running on this host ?\n", UNIX_PATH, strerror(errno) );
		close( unix_if.unix_sock );
		exit(EXIT_FAILURE);

	}

	send_buff = malloc( sbsize );
	memset(send_buff, '\0', sbsize );
	rec_buff = malloc( rbsize );
	memset(rec_buff, '\0', rbsize );


	memcpy( &icmp_packet.dst,mac,6 );
	icmp_packet.packet_type = 1;
	icmp_packet.msg_type = ECHO_REQUEST;
	icmp_packet.ttl = 20;
	icmp_packet.seqno = 11;

	memcpy( send_buff, begin, 2 );
	memcpy( send_buff+2, &icmp_packet, rbsize );

	if ( write( unix_if.unix_sock, send_buff, sbsize ) < 0 ) {
		printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
		close( unix_if.unix_sock );
		free( send_buff);
		exit(EXIT_FAILURE);
	}

	while ( ( recv_buff_len = read( unix_if.unix_sock, rec_buff, rbsize ) ) > 0 ) {
		printf("receive %d bytes\n", recv_buff_len );
		if( recv_buff_len != rbsize )
			break;
		if( ( (struct icmp_packet *)rec_buff)->msg_type == DESTINATION_UNREACHABLE ) {
			printf("Host unreachable\n");
			break;
		}

		printf("%d %d\n", ((struct icmp_packet *)rec_buff)->msg_type,((struct icmp_packet *)rec_buff)->seqno );
	}
	return;
}
