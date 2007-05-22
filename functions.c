#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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
