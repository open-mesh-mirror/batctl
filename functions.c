#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/ether.h>

#include "functions.h"

int convert_mac( char mac_string[], uint8_t mac[] ) {
	struct ether_addr *tmp;
	tmp = ether_aton( mac_string );
	if( tmp == NULL )
		return -1;
	else {
		memcpy( mac, tmp, 6 );
		return 0;
	}
}

double time_diff( struct timeval *start, struct timeval *end ) {
	unsigned long sec = (unsigned long) end->tv_sec - start->tv_sec;
	unsigned long usec = (unsigned long)end->tv_usec - start->tv_usec;

	if(sec > end->tv_sec) {
		sec += 1000000000UL;
		--sec;
	}

	if(usec>end->tv_usec) {
		usec += 1000000000UL;
		--usec;
	}

	if ( sec > 0 )
		usec = 1000000 * sec + usec;

	return (double)usec/1000;
}

void convert_mac_i( uint8_t  mac[], char string[] ) {
	char *tmp;
	tmp = ether_ntoa( (struct ether_addr*)mac );
	memcpy( string, tmp, 18 );
}
