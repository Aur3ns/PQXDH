CC ?= gcc

CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CPPFLAGS ?= -I/usr/local/include -Ilibxeddsa/include -Ilibxeddsa/ref10/include
LDFLAGS ?= -L/usr/local/lib
LDLIBS ?= libxeddsa/bin/static/libxeddsa.a -lsodium -lssl -lcrypto -loqs -lpthread

.PHONY: all test clean

all: libxeddsa/bin/static/libxeddsa.a libpqxdh.a test_pqxdh

libxeddsa/bin/static/libxeddsa.a:
	cmake -S libxeddsa -B libxeddsa/build -DBUILD_TESTING=OFF
	cmake --build libxeddsa/build --target xeddsa_static

pqxdh.o: pqxdh.c pqxdh.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c pqxdh.c -o $@

test_pqxdh.o: test_pqxdh.c pqxdh.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c test_pqxdh.c -o $@

libpqxdh.a: pqxdh.o
	$(AR) rcs $@ $^

test_pqxdh: test_pqxdh.o libpqxdh.a libxeddsa/bin/static/libxeddsa.a
	$(CC) $(LDFLAGS) -o $@ test_pqxdh.o libpqxdh.a $(LDLIBS)

test: test_pqxdh
	./test_pqxdh

clean:
	rm -f *.o *.a test_pqxdh
