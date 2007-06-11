#include <stdint.h>
#include <stdlib.h>

#include "functions.h"

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
