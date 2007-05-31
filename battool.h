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

#include <sys/un.h>
#include "packet.h"

#define UNIX_PATH "/var/run/batmand-adv.socket"

#define SOURCE_VERSION "0.1-alpha"

struct unix_if {
	int32_t unix_sock;
	struct sockaddr_un addr;
};

int ping_main( int argc, char **argv );
int traceroute_main( int argc, char **argv );

extern uint8_t Stop;
