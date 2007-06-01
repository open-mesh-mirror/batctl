#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "functions.h"

int convert_mac( char mac_string[], uint8_t mac[] ) {
	int i, j=0;
	char tmp[2];

	if( strlen( mac_string ) > 17 )
		return -1;

	for( i = 0; i < strlen( mac_string ) ; ) {
		if( mac_string[i] != ':' ) {
			tmp[0] = mac_string[i];
		} else {
			mac[j] = 0;
			i++;
			j++;
			continue;
		}

		if( mac_string[i+1] != ':' ) {
			tmp[1] = mac_string[i+1];
			i+=3;
		} else {
			tmp[1] = tmp[0];
			tmp[0] = '0';
			i+=2;
		}

		mac[j] = strtol(tmp,NULL,16);
		j++;
	}

	if( j < 5 || j > 6 )
		return -1;

	return 1;
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
	snprintf( string, 17, "%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] );
}
