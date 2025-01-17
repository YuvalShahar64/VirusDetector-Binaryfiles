CC=gcc
CFLAGS=-Wall -g

all: AntiVirus

AntiVirus: AntiVirus.o
	$(CC) $(CFLAGS) -o AntiVirus AntiVirus.o

AntiVirus.o: AntiVirus.c
	$(CC) $(CFLAGS) -c AntiVirus.c

clean:
	rm -f AntiVirus AntiVirus.o

.PHONY: clean

valgrind: AntiVirus
	valgrind --leak-check=full --track-origins=yes --show-reachable=yes ./AntiVirus