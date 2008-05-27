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
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <time.h>

#include "battool.h"
#include "batdump.h"

#define UNIDIRECTIONAL 0x80
#define DIRECTLINK 0x40


uint8_t verbose = 0;
uint8_t print_names = 1;

struct list_head_first dump_if_list;

void batdump_usage() {
	printf("Battool module batdump\n");
	printf("Usage: battool batdump|bd [option] interface\n");
	printf("\t-p packet type\n\t\t1=batman packets\n\t\t2=icmp packets\n\t\t3=unicast packets\n\t\t4=broadcast packets\n");
	printf("\t-a all packet types\n");
	printf("\t-d packet dump in hex\n");
	printf("\t-v verbose\n");
	printf("\t-n don't convert addesses to names\n");
	printf("\t-h help\n");
	return;
}

void print_arp( unsigned char *buff, struct hashtable_t *hash ) {
	struct my_arphdr *arp = (struct my_arphdr*)buff;
	printf("ARP %u.%u.%u.%u", arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3] );
	switch( ntohs( arp->ar_op ) ) {
		case ARPOP_REQUEST:
			printf(" ARP_REQUEST");
			break;
		case ARPOP_REPLY:
			printf(" ARP_REPLY");
			break;
		default:
			printf("unknown");
	}
	printf("(%u) %u.%u.%u.%u\n",ntohs( arp->ar_op ), arp->ar_tip[0], arp->ar_tip[1], arp->ar_tip[2], arp->ar_tip[3]);
	return;
}

void print_ether( unsigned char *buff, struct hashtable_t *hash ) {

	struct ether_header *eth = (struct ether_header*)buff;
	struct hosts *tmp_host;
	struct tm *tm;
	time_t tnow;

	char *name_shost = NULL, *name_dhost = NULL;

	/* get localtime */
	time( &tnow );
	tm = localtime(&tnow);

	if(print_names) {

		tmp_host = ((struct hosts *)hash_find(hash, eth->ether_shost ));

		if(tmp_host != NULL)
			name_shost = tmp_host->name;

		tmp_host = ((struct hosts *)hash_find(hash, eth->ether_dhost ));

		if(tmp_host != NULL)
			name_dhost = tmp_host->name;

	}

	printf("%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec );

	if(!name_shost)
		name_shost = ether_ntoa( (struct ether_addr *) eth->ether_shost );
	
	printf("%s -> ", name_shost );

	if(!name_dhost)
		name_dhost = ether_ntoa( (struct ether_addr *)eth->ether_dhost );

	printf("%s ", name_dhost );
	
	return;
}

void print_batman_packet( unsigned char *buff, struct hashtable_t *hash ) {
	struct batman_packet *bp = (struct batman_packet *) buff;
	struct hosts *tmp_host;
	char *name_orig = NULL, *name_old_orig=NULL;

	if(print_names) {

		tmp_host = ((struct hosts *)hash_find(hash, (struct ether_addr*) bp->orig));
		if(tmp_host != NULL)
			name_orig = tmp_host->name;

		tmp_host = ((struct hosts *)hash_find(hash, (struct ether_addr*) bp->old_orig));
		if(tmp_host != NULL)
			name_old_orig = tmp_host->name;

	}

	if(!name_orig)
		name_orig = ether_ntoa((struct ether_addr*) bp->orig);
	
	printf("BAT %s ", name_orig);

	if(!name_old_orig)
		name_old_orig = ether_ntoa((struct ether_addr*) bp->old_orig);
	
	printf("%s (seqno %d, tq %d, TTL %d, V %d, UD %d, DL %d)\n", name_old_orig, ntohs(bp->seqno), bp->tq,
	       bp->ttl, bp->version, (bp->flags & UNIDIRECTIONAL ? 1 : 0), (bp->flags & DIRECTLINK ? 1 : 0));

	return;
}

void print_icmp_packet( unsigned char *buff, struct hashtable_t *hash ) {
	struct icmp_packet *ip = ( struct icmp_packet * )buff;
	struct hosts *tmp_host;
	char *name_orig = NULL, *name_dst=NULL;

	if(print_names) {

		tmp_host = ((struct hosts *)hash_find(hash, (struct ether_addr*) ip->orig));

		if(tmp_host != NULL)
			name_orig = tmp_host->name;

		tmp_host = ((struct hosts *)hash_find(hash, (struct ether_addr*) ip->dst));

		if(tmp_host != NULL)
			name_dst = tmp_host->name;

	}

	if(!name_orig)
		name_orig = ether_ntoa((struct ether_addr*) ip->orig);

	printf("BAT_ICMP %s", name_orig );

	switch( ip->msg_type ) {
		case ECHO_REPLY:
			printf(" ERP");
			break;
		case DESTINATION_UNREACHABLE:
			printf(" DUR");
			break;
		case ECHO_REQUEST:
			printf(" ERQ");
			break;
		case TTL_EXCEEDED:
			printf(" TTL");
			break;
		default:
			printf("unknown");
	}

	if(!name_dst)
		name_dst = ether_ntoa((struct ether_addr*) ip->dst );
	
	printf(" %s\n", name_dst );
	return;
}

void print_unicast_packet( unsigned char *buff, struct hashtable_t *hash ) {
	struct ether_header *eth1 = (struct ether_header*) ( buff + sizeof( struct unicast_packet) );

	if( ntohs( eth1->ether_type ) == ETH_P_IP ) {
		struct ip *ip = (struct ip*) ( buff + ( sizeof(struct ether_header) ) + sizeof(struct unicast_packet ) );
		printf("BAT_UNI IP V%u %s -> ", ip->ip_v, inet_ntoa( ip->ip_src) );
		printf("%s ", inet_ntoa( ip->ip_dst ) );
		switch( ip->ip_p ) {
			case ICMP:
				printf("ICMP\n");
				break;
			case TCP:
				printf("TCP\n");
				break;
			case UDP:
				printf("UDP\n");
				break;
			default:
				printf("unknown IP protocol\n");
		}
	} else if( ntohs( eth1->ether_type ) == ETH_P_ARP ) {
		printf("BAT_UNI ");
		print_arp( buff + sizeof( struct unicast_packet ) + sizeof( struct ether_header ), hash );
	} else {
		printf("BAT_UNI unknow ether type %x\n", ntohs( eth1->ether_type ) );
	}

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
	printf("\n\n");
	return;
}

void print_broadcast_packet( unsigned char *buff, struct hashtable_t *hash ) {

	struct bcast_packet *bc = (struct bcast_packet*)buff;
	struct hosts *tmp_host;
	char *name_orig = NULL;

	if(print_names) {
		tmp_host = ((struct hosts *)hash_find(hash, (struct ether_addr*) bc->orig));
		if(tmp_host != NULL)
			name_orig = tmp_host->name;
	}

	if(!name_orig)
		name_orig = ether_ntoa((struct ether_addr*) bc->orig);

	printf("BAT_BCAST %s", name_orig );


	if( ntohs(((struct ether_header*)(buff + sizeof( struct bcast_packet )))->ether_type) == ETH_P_ARP )
		print_arp( buff + sizeof( struct bcast_packet ) + sizeof( struct ether_header ), hash );
// 		if( verbose ) {
// 			printf("\n\tether source = %s",ether_ntoa( (struct ether_addr *) eth->ether_shost ) );
// 			printf(" ether dest. = %s", ether_ntoa( (struct ether_addr *)eth->ether_dhost ) );
// 			printf("\n\tsender = %s %u.%u.%u.%u\n\ttarget = %s %u.%u.%u.%u\n", ether_ntoa((struct ether_addr*) arp->ar_sha ),arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3],
// 			 ether_ntoa((struct ether_addr*) arp->ar_tha ),arp->ar_tip[0], arp->ar_tip[1], arp->ar_tip[2], arp->ar_tip[3]);
// 		} else
			printf("\n");

}

int batdump_main( int argc, char **argv, struct hashtable_t *hash )
{
	int  optchar,
		packetsize = 2000,
		ptype=0,
		tmp,
		max_sock=0;

	unsigned char packet[packetsize];
	uint8_t found_args = 1,
			print_dump = 0;

	ssize_t rec_length; /* packet length */

	uint16_t proto = ETH_P_BATMAN,  /* default batman packets */
		etype; /* ethernet type */

	struct timeval tv;
	struct ifreq req;
	struct dump_if *dump_if; /* list of interfaces */
	struct list_head *list_pos;
	fd_set wait_sockets, tmp_wait_sockets;
	struct batman_packet *batman_packet;

	void (*p)(unsigned char*, struct hashtable_t *hash); /* pointer for packet output functions */


	while ( ( optchar = getopt ( argc, argv, "advnp:h" ) ) != -1 ) {
		switch( optchar ) {
			case 'a':
				proto = ETH_P_ALL;
				found_args+=1;
				break;
			case 'd':
    				print_dump = 1;
				found_args+=1;
				break;
			case 'v':
    				verbose = 1;
				found_args+=1;
				break;
			case 'n':
				print_names = 0;
				found_args+=1;
				break;
			case 'p':
				tmp = strtol(optarg, NULL , 10);
				if( tmp > 0 && tmp < 5 )
					ptype = tmp;
				found_args+=2;
				break;
			case 'h':
				batdump_usage();
				exit(EXIT_SUCCESS);
				break;
			default:
				batdump_usage();
				exit(EXIT_FAILURE);
		}
	}

	if ( argc <= found_args ) {
		batdump_usage();
		exit(EXIT_FAILURE);
	}

	INIT_LIST_HEAD_FIRST( dump_if_list ); /* init interfaces list */
	FD_ZERO(&wait_sockets);

	while ( argc > found_args ) {

		dump_if = malloc( sizeof(struct dump_if) );
		memset( dump_if, 0, sizeof(struct dump_if) );
		INIT_LIST_HEAD( &dump_if->list );

		dump_if->dev = argv[found_args];

		if ( strlen( dump_if->dev ) > IFNAMSIZ - 1 ) {
			printf( "Error - interface name too long: %s\n", dump_if->dev );
			exit( EXIT_FAILURE );
		}

		if ( ( dump_if->raw_sock = socket(PF_PACKET,SOCK_RAW, htons( ETH_P_ALL ) ) ) < 0 ) {
			printf("Error - can't create raw socket: %s\n", strerror(errno) );
			exit( EXIT_FAILURE );
		}
		memset( &req, 0, sizeof ( struct ifreq ) );
		strncpy(req.ifr_name, dump_if->dev, IFNAMSIZ);

		if ( ioctl(dump_if->raw_sock, SIOCGIFINDEX, &req) < 0 ) {
			printf("Error - can't create raw socket (SIOCGIFINDEX): %s\n", strerror(errno) );
			exit( EXIT_FAILURE );
		}
		dump_if->addr.sll_family   = AF_PACKET;
		dump_if->addr.sll_protocol = htons( ETH_P_ALL );
		dump_if->addr.sll_ifindex  = req.ifr_ifindex;

		if ( bind( dump_if->raw_sock, ( struct sockaddr *)&dump_if->addr, sizeof( struct sockaddr_ll ) ) < 0 ) {
			printf( "Error - can't bind raw socket: %s\n", strerror(errno) );
			close( dump_if->raw_sock );
			exit( EXIT_FAILURE );
		}

		if ( dump_if->raw_sock > max_sock )
			max_sock = dump_if->raw_sock;

		FD_SET(dump_if->raw_sock, &wait_sockets);
		list_add_tail( &dump_if->list, &dump_if_list );
		found_args++;

	}

	while(1) {

		memcpy( &tmp_wait_sockets, &wait_sockets, sizeof( fd_set ) );
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		if ( select( max_sock + 1, &tmp_wait_sockets, NULL, NULL, &tv ) > 0 ) {

			list_for_each( list_pos, &dump_if_list ) {

				dump_if = list_entry( list_pos, struct dump_if, list );

				if ( FD_ISSET( dump_if->raw_sock, &tmp_wait_sockets ) ) {

					rec_length = read( dump_if->raw_sock, packet, packetsize );
					etype = ntohs(((struct ether_header*)packet)->ether_type);
					p = NULL;

					if( proto == ETH_P_ALL && etype == ETH_P_ARP )
						p = print_arp;

// 					else if( etype == ETH_P_IP )
// 						printf("ip comming soon\n");

					else if( etype == ETH_P_BATMAN ) {
						batman_packet = (struct batman_packet *)(packet + sizeof(struct ether_header));

						if (batman_packet->version != COMPAT_VERSION)
							continue;

						if ((batman_packet->packet_type == BAT_PACKET) && (ptype == 0 || ptype == BAT_PACKET))

							p = print_batman_packet;

						else if ((batman_packet->packet_type == BAT_ICMP) && (ptype == 0 || ptype == BAT_ICMP))

							p = print_icmp_packet;

						else if ((batman_packet->packet_type == BAT_UNICAST) && (ptype == 0 || ptype == BAT_UNICAST))

							p = print_unicast_packet;

						else if ((batman_packet->packet_type == BAT_BCAST) && (ptype == 0 || ptype == BAT_BCAST))

							p = print_broadcast_packet;

					}

					if( p != NULL ) {
						printf("%d ", rec_length);
						print_ether(packet, hash);
						(*p)( ( packet + sizeof(struct ether_header) ), hash );
						if(print_dump)
							print_packet( rec_length, packet );
					}

				}
			}
		}

	}

	exit( EXIT_SUCCESS );
}
