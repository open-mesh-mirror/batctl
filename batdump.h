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

#include "list-batman.h"

#define	ARPOP_REQUEST	1		/* ARP request.  */
#define	ARPOP_REPLY	2		/* ARP reply.  */
#define	ARPOP_RREQUEST	3		/* RARP request.  */
#define	ARPOP_RREPLY	4		/* RARP reply.  */
#define	ARPOP_InREQUEST	8		/* InARP request.  */
#define	ARPOP_InREPLY	9		/* InARP reply.  */
#define	ARPOP_NAK	10		/* (ATM)ARP NAK.  */

/* protocol numbers */
#define ICMP 0x01
#define TCP 0x06
#define UDP 0x11

struct my_arphdr
{
	uint16_t ar_hrd; /* format of hardware address */
	uint16_t ar_pro; /* format of protocol address */
	uint8_t ar_hln; /* length of hardware address */
	uint8_t ar_pln; /* length of protocol address */
	uint16_t ar_op; /* ARP opcode (command) */

	uint8_t ar_sha[ETH_ALEN]; /* sender hardware address */
	uint8_t ar_sip[4]; /* sender IP address */
	uint8_t ar_tha[ETH_ALEN]; /* target hardware address */
	uint8_t ar_tip[4]; /* target IP address */
};

struct dump_if {
	struct list_head list;
	char *dev;
	int32_t raw_sock;
	struct sockaddr_ll addr;
};
