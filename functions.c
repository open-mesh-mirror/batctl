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


#include <stdint.h>
#include <stdlib.h>

#include "functions.h"

double time_diff( struct timeval *start, struct timeval *end ) {
	unsigned long sec = (unsigned long) end->tv_sec - start->tv_sec;
	unsigned long usec = (unsigned long)end->tv_usec - start->tv_usec;

	if(sec > (unsigned long)end->tv_sec) {
		sec += 1000000000UL;
		--sec;
	}

	if(usec > (unsigned long)end->tv_usec) {
		usec += 1000000000UL;
		--usec;
	}

	if ( sec > 0 )
		usec = 1000000 * sec + usec;

	return (double)usec/1000;
}
