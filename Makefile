CC=gcc
CFLAGS= -Wall -O0 -g3

battool: battool.o ping.o functions.o

battool.o: battool.c battool.h

functions.o: functions.c functions.h

ping.o: ping.c battool.h

clean:
	rm -f battool *.o *~
