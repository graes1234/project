//thread, 1대1
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

struct thread_arg {
    int sock;
};

void *recv_thread_fn(void *arg) {
    int sock = *((int*)arg);
    char buf[BUF_SIZE];
    while (!stopped) {
        ssize_t n = read(sock, buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            printf("%s", buf); // client already includes newline
            fflush(stdout);
        } else if (n == 0) {
            // peer closed
            fprintf(stderr, "\n[INFO] Client disconnected\n");
            stopped = 1;
            break;
        } else {
            // error
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
        // if user types q or Q alone -> quit
        if ((strcmp(line, "q\n") == 0) || (strcmp(line, "Q\n") == 0)) {
            stopped = 1;
            // polite shutdown so peer sees EOF
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
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) error_handling("socket");

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1])); // IMPORTANT: htons

    if (bind(listen_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        error_handling("bind");

    if (listen(listen_sock, 1) < 0)
        error_handling("listen");

    printf("Server listening on port %s\n", argv[1]);
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_sz = sizeof(clnt_addr);
    int conn_sock = accept(listen_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_sz);
    if (conn_sock < 0) error_handling("accept");

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clnt_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("Client connected: %s:%d\n", client_ip, ntohs(clnt_addr.sin_port));

    pthread_t tid_recv, tid_send;

    // Use conn_sock address for both threads
    if (pthread_create(&tid_recv, NULL, recv_thread_fn, &conn_sock) != 0)
        error_handling("pthread_create (recv)");
    if (pthread_create(&tid_send, NULL, send_thread_fn, &conn_sock) != 0)
        error_handling("pthread_create (send)");

    // Join threads
    pthread_join(tid_send, NULL);
    // if send thread ended first, ensure socket shutdown to wake recv thread
    stopped = 1;
    shutdown(conn_sock, SHUT_RDWR);
    pthread_join(tid_recv, NULL);

    close(conn_sock);
    close(listen_sock);
    printf("Server exiting\n");
    return 0;
}
