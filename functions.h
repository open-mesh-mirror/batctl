/* converts a mac address string to int[6] array */
int convert_mac( char *mac_string, uint8_t *mac );

/* return time delta from start to end in milliseconds */
double time_diff( struct timeval *start, struct timeval *end );
