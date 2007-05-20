CC=gcc
CFLAGS= -Wall -O0 -g3

battool: battool.o ping.o

battool.o: battool.c battool.h

ping.o: ping.c battool.h

clean:
	rm -f battool *.o *~
