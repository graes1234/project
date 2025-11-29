//1대1 기본 version2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

void error_handling(char *message);

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in serv_adr;
    char message[30];
    int str_len;

    if(argc!=3) {
        printf("Usage : %s <IP> <port>\n", argv[0]);
        exit(1);
    }

    //client 공통
    sock=socket(PF_INET, SOCK_STREAM, 0);
    if(sock == -1)
        error_handling("socket() error");

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family=AF_INET;
    serv_adr.sin_addr.s_addr=inet_addr(argv[1]);
    serv_adr.sin_port=htons(atoi(argv[2]));

    //connect
    if(connect(sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
        error_handling("connect() error");
    //##

    //read
    str_len=read(sock, message, sizeof(message)-1);
    if(str_len == -1)
        error_handling("read() error");

    printf("Message from server: %s \n", message);
    close(sock);
    return 0;
}

void error_handling(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

//thread 기반
// client_1to1.c
// Compile: gcc -Wall -Wextra client_1to1.c -o client_1to1 -pthread
// Run: ./client_1to1 <server_ip> <port>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

#define BUF_SIZE 1024

volatile sig_atomic_t stopped = 0;

void error_handling(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void *recv_thread_fn(void *arg) {
    int sock = *((int*)arg);
    char buf[BUF_SIZE];
    while (!stopped) {
        ssize_t n = read(sock, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        } else if (n == 0) {
            fprintf(stderr, "\n[INFO] Server closed connection\n");
            stopped = 1;
            break;
        } else {
            if (!stopped) perror("read");
            stopped = 1;
            break;
        }
    }
    return NULL;
}

void *send_thread_fn(void *arg) {
    int sock = *((int*)arg);
    char line[BUF_SIZE];
    while (!stopped && fgets(line, sizeof(line), stdin) != NULL) {
        if ((strcmp(line, "q\n") == 0) || (strcmp(line, "Q\n") == 0)) {
            stopped = 1;
            shutdown(sock, SHUT_WR);
            break;
        }
        ssize_t to_write = strlen(line);
        ssize_t w = write(sock, line, to_write);
        if (w < 0) {
            perror("write");
            stopped = 1;
            break;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <port>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_handling("socket");

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
        error_handling("inet_pton");

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        error_handling("connect");

    printf("Connected to %s:%s\n", argv[1], argv[2]);

    pthread_t tid_recv, tid_send;
    if (pthread_create(&tid_recv, NULL, recv_thread_fn, &sock) != 0)
        error_handling("pthread_create (recv)");
    if (pthread_create(&tid_send, NULL, send_thread_fn, &sock) != 0)
        error_handling("pthread_create (send)");

    pthread_join(tid_send, NULL);
    stopped = 1;
    shutdown(sock, SHUT_RDWR);
    pthread_join(tid_recv, NULL);

    close(sock);
    printf("Client exiting\n");
    return 0;
}



