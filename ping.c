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
#include <sys/time.h>
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

void ping_main( uint8_t *mac, char *mac_string ) {

	char *send_buff, *rec_buff;
	char begin[] = "p:";
	int sbsize,rbsize;
	uint8_t res;
	int32_t recv_buff_len;
	struct icmp_packet icmp_packet;
	struct unix_if unix_if;
	struct timeval timeout,start,end;
	double time_delta;

	fd_set read_socket;
 	unsigned long sec,usec;
	
	int trans=0, recv=0, avg_count=0;
	float min= -1.0, avg=0.0, max=0.0;

	
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
	icmp_packet.ttl = 50;
	icmp_packet.seqno = 0;

	memcpy( send_buff, begin, 2 );
	printf("PING %s\n", mac_string );
	while( !Stop ) {

		icmp_packet.seqno++;
		memcpy( send_buff+2, &icmp_packet, rbsize );
		
		if ( write( unix_if.unix_sock, send_buff, sbsize ) < 0 ) {
			printf( "Error - can't write to unix socket: %s\n", strerror(errno) );
			close( unix_if.unix_sock );
			free( send_buff);
			exit(EXIT_FAILURE);
		}

		gettimeofday(&start,(struct timezone*)0);
	 	trans++;

		timeout.tv_sec = 2;
		timeout.tv_usec = 0;
		FD_ZERO(&read_socket);
		FD_SET( unix_if.unix_sock, &read_socket );
		res = select( unix_if.unix_sock + 1, &read_socket, NULL, NULL, &timeout );

		if( res > 0 )
		{
			
			if ( ( recv_buff_len = read( unix_if.unix_sock, rec_buff, rbsize ) ) > 0 )
			{
				gettimeofday(&end,(struct timezone*)0);
				if( recv_buff_len == rbsize && ((struct icmp_packet *)rec_buff)->msg_type == ECHO_REPLY )
				{
					
					sec = (unsigned long)end.tv_sec - start.tv_sec;
					if(sec>end.tv_sec) {
						sec += 1000000000UL;
						--sec;
					}
				
					usec = (unsigned long)end.tv_usec - start.tv_usec;
					if(usec>end.tv_usec) {
						usec += 1000000000UL;
						--usec;
					}

					if ( sec > 0 )
						usec = 1000000 * sec + usec;
			
					time_delta = (double)usec/1000;
					printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.2f ms\n",recv_buff_len, mac_string, ((struct icmp_packet *)rec_buff)->seqno,((struct icmp_packet *)rec_buff)->ttl, time_delta );

					/* statistic */
					if( time_delta < min || min == -1.0 ) min = time_delta;
					if( time_delta > max ) max = time_delta;
					avg += time_delta;
					avg_count++;
					recv++;
				} else {
		
					if( ( (struct icmp_packet *)rec_buff)->msg_type == DESTINATION_UNREACHABLE )
						printf("Host %s is unreachable\n", mac_string );
					else
						printf("%d\n", ( (struct icmp_packet *)rec_buff)->msg_type );
				}
			}

		} else if ( res == 0 ) {
			printf("Host %s timeout\n",mac_string );
		}
		sleep(1);
	}
	printf("--- %s ping statistic ---\n",mac_string );
	printf("%d packets transmitted, %d received, %d%c packet loss\n", trans, recv, ( (trans - recv) * 100 / trans ),'%');
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min, (avg / avg_count),max, max-min );
	return;
}
