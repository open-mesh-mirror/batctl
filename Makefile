CC=gcc
CFLAGS= -Wall -O0 -g3

battool: battool.o ping.o functions.o traceroute.o

battool.o: battool.c battool.h

functions.o: functions.c functions.h

ping.o: ping.c

traceroute.o: traceroute.c

clean:
	rm -f battool *.o *~
