CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lsodium -lssl -lcrypto -loqs

all: test_pqxdh

pqxdh.o: pqxdh.c pqxdh.h
	$(CC) $(CFLAGS) -c pqxdh.c

test_pqxdh.o: test_pqxdh.c pqxdh.h
	$(CC) $(CFLAGS) -c test_pqxdh.c

test_pqxdh: pqxdh.o test_pqxdh.o
	$(CC) $(CFLAGS) -o test_pqxdh pqxdh.o test_pqxdh.o $(LDFLAGS)

clean:
	rm -f *.o test_pqxdh
