// Compile: gcc plain_server.c -o plain_server
// Run: ./plain_server 4444
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT_DEF 4444
#define BUF 2048

int main(int argc, char **argv) {
    int port = (argc>1)?atoi(argv[1]):PORT_DEF;
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in serv = {0}, cli = {0};
    serv.sin_family = AF_INET; serv.sin_addr.s_addr = INADDR_ANY; serv.sin_port = htons(port);
    bind(listenfd, (struct sockaddr*)&serv, sizeof(serv));
    listen(listenfd, 1);
    printf("Plain server listening on %d\n", port);
    socklen_t clilen = sizeof(cli);
    int conn = accept(listenfd, (struct sockaddr*)&cli, &clilen);
    if (conn < 0) { perror("accept"); return 1; }
    printf("Client connected\n");
    char buf[BUF];
    while (1) {
        ssize_t r = read(conn, buf, BUF-1);
        if (r <= 0) break;
        buf[r] = 0;
        printf("[Client] %s\n", buf);
        // echo back
        write(conn, buf, r);
    }
    close(conn); close(listenfd);
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
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;

    char message[]="Hello world!";

    if(argc!=2) {
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    //server 공통
    serv_sock=socket(PF_INET, SOCK_STREAM, 0);
    if(serv_sock == -1)
        error_handling("socket() error");

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family=AF_INET;
    serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
    serv_adr.sin_port=htons(atoi(argv[1]));
    //##

    if(bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
        error_handling("bind() error");

    if(listen(serv_sock, 5)== -1)
        error_handling("listen() error");
    clnt_adr_sz=sizeof(clnt_adr);
    //##

    //accept
    clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
    if(clnt_sock==-1)
        error_handling("accept() error");

    //write
    write(clnt_sock, message, sizeof(message)); //##
    close(clnt_sock);
    close(serv_sock);
    return 0;
}

void error_handling(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

