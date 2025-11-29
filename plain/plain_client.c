// Compile: gcc plain_client.c -o plain_client
// Run: ./plain_client 127.0.0.1 4444
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUF 2048

int main(int argc, char **argv) {
    if (argc < 3) { printf("Usage: %s <ip> <port>\n", argv[0]); return 1; }
    const char *ip = argv[1]; int port = atoi(argv[2]);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv = {0};
    serv.sin_family = AF_INET; serv.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv.sin_addr);
    if (connect(sock, (struct sockaddr*)&serv, sizeof(serv)) < 0) { perror("connect"); return 1; }
    printf("Connected to %s:%d\n", ip, port);
    char line[BUF];
    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strlen(line);
        if (n == 0) continue;
        write(sock, line, n);
        ssize_t r = read(sock, line, sizeof(line)-1);
        if (r <= 0) break;
        line[r] = 0;
        printf("[Server] %s\n", line);
    }
    close(sock);
    return 0;
}

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

