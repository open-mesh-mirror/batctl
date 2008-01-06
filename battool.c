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
	printf("module: ping|batping|bp traceroute|batroute|br batdump|bd\n");
	printf("Use \"battool module -h\" for available options\n");
	exit(EXIT_FAILURE);
}

int compare_mac(void *data1, void *data2)
{
	return ( memcmp( data1, data2, sizeof(struct ether_addr) ) );
}

int choose_mac(void *data, int32_t size)
{
	unsigned char *key= data;
	uint32_t hash = 0, m_size = sizeof(struct ether_addr);
	size_t i;

	for (i = 0; i < m_size; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (hash%size);

}

void parse_hosts_file( struct hashtable_t *hash, char path[] ) {

	FILE *fd;
	char name[50], mac[18];
	struct ether_addr *tmp_mac;
	struct hosts *tmp_hosts;
	struct hashtable_t *swaphash;

	name[0] = mac[0] = '\0';

	if( ( fd = fopen(path, "r") ) == NULL )
		return;

	while( fscanf(fd,"%[^ \t]%s\n", name, mac ) != EOF ) {

		if( ( tmp_mac = ether_aton( mac ) ) == NULL ) {
			DBG("the mac address was not correct");
			return;
		}

		if( ( tmp_hosts = malloc(sizeof(struct hosts) ) ) == NULL ) {
			DBG("not enough memory for malloc");
			return;
		}


		memcpy(&tmp_hosts->mac, tmp_mac, sizeof(struct ether_addr));
		strncpy( tmp_hosts->name, name, 49 );

		hash_add(hash, tmp_hosts);

		if (hash->elements * 4 > hash->size) {

			swaphash = hash_resize(hash, hash->size * 2);

			if (swaphash == NULL) {

				printf("Couldn't resize hash table\n");

			}

			hash = swaphash;

		}

	}

	return;

}

int main( int argc, char **argv ) {
	int uid, ret=0;

	struct hashtable_t *host_hash;
	
	if( argc < 2 ) {
		usage();
	}

	if( strcmp( argv[1], "-v" ) == 0 ) {
		printf("Battool %s\n", VERSION);
		exit(EXIT_SUCCESS);
	}


	uid = getuid();
	if(uid != 0) { printf("You must have UID 0 instead of %d.\n",uid); exit(EXIT_FAILURE); }

	host_hash = hash_new( 64, compare_mac, choose_mac );

	parse_hosts_file( host_hash,HOSTS_FILE );
	
	if (strcmp(argv[1], "ping") == 0 ||strcmp(argv[1], "batping") == 0 || strcmp(argv[1], "bp") == 0 ) {
		/* call ping main function */
		ret = batping_main( argc-1, argv+1, host_hash );

	} else if(strcmp(argv[1], "traceroute") == 0 || strcmp(argv[1], "batroute") == 0 || strcmp(argv[1], "br") == 0  ) {
		/* call trace main function */
		ret = batroute_main( argc-1, argv+1, host_hash );

	} else if( strcmp(argv[1], "batdump") == 0 || strcmp(argv[1], "bd") == 0  ) {
		/* call trace main function */
		ret = batdump_main( argc-1, argv+1, host_hash );

	} else {

		usage();

	}

	hash_destroy(host_hash);
	return(ret);
}
