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

#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <features.h>
#include <fcntl.h>
#include "battool.h"
#include "functions.h"

uint8_t Stop = 0;

void batping_usage() {
	printf("Battool module batping\n");
	printf("Usage: battool batping|bp [options] mac|name\n");
	printf("\t-c count\n");
	printf("\t-h help\n");
	printf("\t-i interval in seconds\n");
	printf("\t-t timeout in seconds\n");
	return;
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

int batping_main( int argc, char **argv, struct hashtable_t *hash ) {

	char *send_buff, *rec_buff;
	char begin[] = "p:";
	int sbsize,rbsize;
	uint8_t res;
	int32_t recv_buff_len;
	uint16_t seq_counter = 0;
	struct icmp_packet icmp_packet;
	struct unix_if unix_if;
	struct timeval start,end,timeout;
	struct ether_addr *mac;

	sigset_t sigmask_old, sigmask_new;
	double time_delta;

	fd_set read_socket;

	int trans=0, recv=0, avg_count=0;
	float min= -1.0, avg=0.0, max=0.0;

	int optchar;
	uint8_t found_args = 1;
	int loop_count = -1;
	int loop_interval = 0;
	int time_out = 1;

	char *mac_string = NULL;
	struct hosts *tmp_hosts;
	struct hash_it_t *hashit = NULL;

	while ( ( optchar = getopt ( argc, argv, "hc:i:t:" ) ) != -1 ) {
		switch( optchar ) {
			case 'h':
				batping_usage();
				return(EXIT_SUCCESS);
				break;
			case 'c':
				loop_count = strtol(optarg, NULL , 10);
				if( loop_count < 1 ) loop_count = -1;
				found_args+=2;
				break;
			case 'i':
				loop_interval = strtol(optarg, NULL , 10);
				found_args+=2;
				break;
			case 't':
				time_out = strtol(optarg, NULL , 10);
				found_args+=2;
				break;
			default:
				batping_usage();
				return(EXIT_FAILURE);
		}
	}

	if ( argc <= found_args ) {
		batping_usage();
		return(EXIT_FAILURE);
	}


	while ( NULL != ( hashit = hash_iterate( hash, hashit ) ) ) {

		tmp_hosts = (struct hosts *)hashit->bucket->data;
		if(strcmp(tmp_hosts->name, argv[found_args]) == 0)
			break;
		else
			tmp_hosts = NULL;
	}

	if( tmp_hosts == NULL ) {

		if( ( mac = ether_aton( argv[found_args] ) ) == NULL ) {
			DBG("the mac address was not correct");
			return(EXIT_FAILURE);
		}

	} else
		mac = &tmp_hosts->mac;

	mac_string = ether_ntoa(mac);
	signal( SIGINT, handler );
	signal( SIGTERM, handler );

	unix_if.unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	memset( &unix_if.addr, 0, sizeof(struct sockaddr_un) );

	unix_if.addr.sun_family = AF_LOCAL;
	strcpy( unix_if.addr.sun_path, UNIX_PATH );


	if( ( unix_if.unix_sock = open( BAT_DEVICE, O_RDWR | O_NONBLOCK ) ) < 0 ) {

		DBG( "can't find character device '%s': %s search for unix socket...\n", BAT_DEVICE, strerror(errno) );

		if ( connect ( unix_if.unix_sock, (struct sockaddr *)&unix_if.addr, sizeof(struct sockaddr_un) ) < 0 ) {

			DBG( "can't connect to unix socket '%s': %s ! Is batmand running on this host ?", UNIX_PATH, strerror(errno) );
			close( unix_if.unix_sock );
			return(EXIT_FAILURE);

		} else {
			sbsize = sizeof( struct icmp_packet ) + 2;
		}

	} else
		sbsize = sizeof( struct icmp_packet );


	rbsize = sizeof( struct icmp_packet );

	send_buff = malloc( sbsize );
	memset(send_buff, '\0', sbsize );
	rec_buff = malloc( rbsize );
	memset(rec_buff, '\0', rbsize );


	memcpy( &icmp_packet.dst,mac, ETH_ALEN );
	icmp_packet.packet_type = BAT_ICMP;
	icmp_packet.version = COMPAT_VERSION;
	icmp_packet.msg_type = ECHO_REQUEST;
	icmp_packet.ttl = 50;
	icmp_packet.seqno = 0;

	if(sbsize != sizeof(struct icmp_packet))
		memcpy( send_buff, begin, 2 );

	/* create new procmask */
	sigemptyset( &sigmask_new );
	sigaddset( &sigmask_new, SIGINT );
	sigaddset( &sigmask_new, SIGTERM );
	/* remove new procmask from current procmask */
	sigprocmask( SIG_UNBLOCK,&sigmask_new, &sigmask_old );

	printf("batping %s\n", mac_string );
	while( !Stop && loop_count != 0 ) {
		if( loop_count > 0 )
			loop_count--;

		icmp_packet.seqno = htons( ++seq_counter );

		if(sbsize != sizeof(struct icmp_packet))
			memcpy( send_buff+2, &icmp_packet, rbsize );
		else
			memcpy( send_buff, &icmp_packet, rbsize );

		if ( write( unix_if.unix_sock, send_buff, sbsize ) < 0 ) {
			printf( "Error - can't write to socket: %s %d\n", strerror(errno), errno );
			close( unix_if.unix_sock );
			free( send_buff);
			return(EXIT_FAILURE);
		}

		gettimeofday(&start,(struct timezone*)0);
	 	trans++;

		timeout.tv_sec = time_out;
		timeout.tv_usec = 0;

		FD_ZERO(&read_socket);
		FD_SET( unix_if.unix_sock, &read_socket );


		res = select( unix_if.unix_sock + 1, &read_socket, NULL, NULL, &timeout );

		if( Stop ) {
			trans--;
			break;
		}

		if( res > 0 )
		{
			if ( ( recv_buff_len = read( unix_if.unix_sock, rec_buff, rbsize ) ) > 0 )
			{
				gettimeofday(&end,(struct timezone*)0);
				if( recv_buff_len == rbsize && ((struct icmp_packet *)rec_buff)->msg_type == ECHO_REPLY )
				{

					time_delta = time_diff( &start, &end );
					printf("%d bytes from %s icmp_seq=%u ttl=%d time=%.2f ms\n",recv_buff_len, mac_string, ntohs( ( ( struct icmp_packet * )rec_buff )->seqno ),((struct icmp_packet *)rec_buff)->ttl, time_delta );

					if( time_delta < min || min == -1.0 ) min = time_delta;
					if( time_delta > max ) max = time_delta;
					avg += time_delta;
					avg_count++;
					recv++;
				} else {

					if( ( (struct icmp_packet *)rec_buff)->msg_type == DESTINATION_UNREACHABLE )
						printf("Host %s is unreachable\n", mac_string );
					else
						printf("message type %d len %d\n", ( (struct icmp_packet *)rec_buff)->msg_type, recv_buff_len );
				}
			}

		} else if ( res == 0 ) {
			printf("Host %s timeout\n",mac_string );
		}
		if( timeout.tv_sec > 0 ) sleep( loop_interval?loop_interval:1 );
	}
	printf("--- %s batping statistic ---\n",mac_string );
	printf("%d packets transmitted, %d received, %d%c packet loss\n", trans, recv, ( (trans - recv) * 100 / trans ),'%');
	printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n", min < 0.0 ? 0.000 : min, avg_count?(avg / avg_count):0.000 ,max, max - ( min < 0.0 ? 0.0:min) );
	return(EXIT_SUCCESS);
}
