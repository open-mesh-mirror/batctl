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
#include <sys/un.h>
#include "hash.h"
#include "packet.h"

#define VERSION "0.1-alpha"  /*put exactly one distinct word inside the string like "0.3-pre-alpha" or "0.3-rc1" or "0.3" */
#define SOURCE_VERSION "0.1-alpha"

#define UNIX_PATH "/var/run/batmand-adv.socket"
#define BAT_DEVICE "/dev/batman-adv"

#define HOSTS_FILE "bat-hosts"
#define DBG(msg,args...) do { printf("batgat: [%s:%u] " msg "\n", __func__ ,__LINE__, ##args); } while(0)

struct unix_if {
	int32_t unix_sock;
	struct sockaddr_un addr;
};

struct hosts {
	struct ether_addr mac;
	char name[50];
};

int batping_main( int argc, char **argv, struct hashtable_t *hash );
int batroute_main( int argc, char **argv, struct hashtable_t *hash );
int batdump_main( int argc, char **argv, struct hashtable_t *hash );
