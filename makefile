CC=gcc
CFLAGS=-Wall -g
LIBS=-lcrypto

all: plain_server plain_client aes_test sha256_test server_full client_full

plain_server: plain_server.c
	$(CC) $(CFLAGS) -o plain_server plain_server.c

plain_client: plain_client.c
	$(CC) $(CFLAGS) -o plain_client plain_client.c

aes_test: aes_test.c
	$(CC) $(CFLAGS) -o aes_test aes_test.c -lcrypto

sha256_test: sha256_test.c
	$(CC) $(CFLAGS) -o sha256_test sha256_test.c -lcrypto

server_full: server_full.c crypto.c
	$(CC) $(CFLAGS) -o server_full server_full.c crypto.c $(LIBS)

client_full: client_full.c crypto.c
	$(CC) $(CFLAGS) -o client_full client_full.c crypto.c $(LIBS)

clean:
	rm -f plain_server plain_client aes_test sha256_test server_full client_full *.o
