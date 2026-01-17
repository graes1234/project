OPENSSL_PATH=$(shell brew --prefix openssl@3)

CC=gcc
CFLAGS=-Wall -g -I/opt/homebrew/opt/openssl@3/include
LDFLAGS=-L/opt/homebrew/opt/openssl@3/lib -lcrypto -lssl
RPATH=-Wl,-rpath,/opt/homebrew/opt/openssl@3/li

all: client_full.c server_full.c

sf: server_full.c crypto.c crypto.h
	$(CC) $(CFLAGS) -o sf server_full.c crypto.c $(LDFLAGS)

cf: client_full.c crypto.c crypto.h
	$(CC) $(CFLAGS) -o cf client_full.c crypto.c $(LDFLAGS)

clean:
	rm -f sf cf *.o

