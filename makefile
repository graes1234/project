CC=gcc
CFLAGS=-Wall -g
LIBS=-lcrypto

all: thread_server.c thread_client.c th_server1.c th_client1.c test_aes.c

ths: thread_server.c
	$(CC) $(CFLAGS) -o ths thread_server.c

thc: thread_client.c
	$(CC) $(CFLAGS) -o thc thread_client.c

th_s1: th_server1.c
	$(CC) $(CFLAGS) -o th_s1 th_server1.c

th_c1: th_client1.c
	$(CC) $(CFLAGS) -o th_c1 th_client1.c

aes_test: test_aes.c
	$(CC) $(CFLAGS) -o aes_test aes_test.c -lcrypto
