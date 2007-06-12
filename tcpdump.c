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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>

#include "battool.h"


void tcpdump_usage() {
	printf("Battool module tcpdump\n");
	printf("Usage: battool tcpdump|td [option] interface\n");
	printf("\t-p packet type\n\t\t1=batman packets\n\t\t2=icmp packets\n\t\t3=unicast packets\n");
	printf("\t-h help\n");
	return;
}

void print_batman_packet( unsigned char *buf)
{
	struct batman_packet *bp = (struct batman_packet *)buf;
	printf("batman header:\n");
	printf(" ptype=%u flags=%x ttl=%u orig=%s seq=%u gwflags=%x version=%u\n", bp->packet_type,bp->flags, bp->ttl, ether_ntoa((struct ether_addr*) bp->orig), ntohs(bp->seqno), bp->gwflags, bp->version );
	return;
}

void print_icmp_packet( unsigned char *buf)
{
	struct icmp_packet *ip = (struct icmp_packet *)buf;
	printf("icmp header:\n");
	printf(" ptype=%u mtype=%u ttl=%u dst=%s", ip->packet_type, ip->msg_type, ip->ttl, ether_ntoa((struct ether_addr*) ip->dst ) );
	printf(" orig=%s seq=%u uid=%u\n", ether_ntoa((struct ether_addr*) ip->orig), ntohs(ip->seqno), ip->uid );
	return;
}

void print_packet( int length, unsigned char *buf )
{
	int i = 0;
	printf("\n");
	for( ; i < length; i++ ) {
		if( i == 0 )
			printf("0000| ");

		if( i != 0 && i%8 == 0 )
			printf("  ");
		if( i != 0 && i%16 == 0 )
			printf("\n%04d| ", i/16*10);

		printf("%02x ", buf[i] );
	}
	printf("\n");
	return;
}

int tcpdump_main( int argc, char **argv )
{
	int  optchar,
		packetsize = 2000,
		ptype=0,
		tmp;

	unsigned char packet[packetsize];
	uint8_t found_args = 1;
	int32_t rawsock;
	ssize_t rec_length;

	struct ether_header *eth = (struct ether_header *) packet;
	struct ifreq req;
	struct sockaddr_ll addr;

	char *devicename;

	while ( ( optchar = getopt ( argc, argv, "p:h" ) ) != -1 ) {
		switch( optchar ) {
			case 'p':
				tmp = strtol(optarg, NULL , 10);
				if( tmp > 0 && tmp < 4 )
					ptype = tmp;
				found_args+=2;
				break;
			case 'h':
				tcpdump_usage();
				exit(EXIT_SUCCESS);
				break;
			default:
				tcpdump_usage();
				exit(EXIT_FAILURE);
		}
	}

	if ( argc <= found_args ) {
		tcpdump_usage();
		exit(EXIT_FAILURE);
	}

	devicename = argv[found_args];

	if ( ( rawsock = socket(PF_PACKET,SOCK_RAW,htons( 0x0842 ) ) ) < 0 ) {
		printf("Error - can't create raw socket: %s\n", strerror(errno) );
		exit( EXIT_FAILURE );
	}

	strncpy(req.ifr_name, devicename, IFNAMSIZ);

	if ( ioctl(rawsock, SIOCGIFINDEX, &req) < 0 ) {
		printf("Error - can't create raw socket (SIOCGIFINDEX): %s\n", strerror(errno) );
		exit( EXIT_FAILURE );
	}

	addr.sll_family   = AF_PACKET;
	addr.sll_protocol = htons( 0x0842 );
	addr.sll_ifindex  = req.ifr_ifindex;

	if ( bind(rawsock, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		printf( "Error - can't bind raw socket: %s\n", strerror(errno) );
		close(rawsock);
		exit( EXIT_FAILURE );
	}

	while( ( rec_length = read(rawsock,packet,packetsize) ) > 0 ) {

		if( !ptype || packet[sizeof( struct ether_header)] + 1 == ptype ) {

			printf("\n---------------------------------------------------------------------------------------\n\n");
			printf("ethernet header:\n");
			printf(" %d bytes dest=%s ", rec_length, ether_ntoa( (struct ether_addr *)eth->ether_dhost ) );
			printf("src=%s type=%04x\n", ether_ntoa( (struct ether_addr *) eth->ether_shost ),  ntohs( eth->ether_type ) );

		}

		if( ( !ptype && packet[sizeof( struct ether_header)] == 0 ) || ( packet[sizeof( struct ether_header)] == 0 && ptype - 1 == 0  ) ) {
			print_batman_packet( packet + sizeof( struct ether_header ) );
			print_packet( rec_length, packet );
		} else if( ( !ptype && packet[sizeof( struct ether_header)] == 1 ) || ( packet[sizeof( struct ether_header)] == 1 && ptype - 1 == 1 ) ) {
			print_icmp_packet( packet + sizeof( struct ether_header ) );
			print_packet( rec_length, packet );
		} else if( ( !ptype && packet[sizeof( struct ether_header)] == 2 ) || ( packet[sizeof( struct ether_header)] == 2 && ptype - 1 == 2 ) ) {
			printf("2 kam\n");
		} else if( ( !ptype && packet[sizeof( struct ether_header)] == 3 ) || ( packet[sizeof( struct ether_header)] == 3 && ptype - 1 == 3 ) ) {
			printf("3 kam\n");
		}

	}

	exit( EXIT_SUCCESS );
}
