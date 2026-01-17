#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <termios.h>
#include <stdint.h>
#include "crypto.h"

#define BUF_SIZE 2048

volatile sig_atomic_t stopped = 0;

int plain_msg_count = 0;

unsigned char session_key[32];
unsigned char session_iv[16];
int session = 0;

char last_encrypted_msg[BUF_SIZE] = {0};
int  decrypt_pending = 0;

pthread_mutex_t decrypt_lock = PTHREAD_MUTEX_INITIALIZER;

RSA *server_priv = NULL;

static void to_hex(const unsigned char *in, int len, char *out) {
    static const char *hex = "0123456789ABCDEF";
    for (int i = 0; i < len; i++) {
        out[i*2]   = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[len*2] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *out) {
    int len = (int)strlen(hex);
    if (len % 2 != 0) return -1;
    for (int i = 0; i < len/2; i++) {
        unsigned int v;
        if (sscanf(&hex[i*2], "%2X", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return len/2;
}

static void input_hidden(char *buf, int maxlen) {
    struct termios oldt, newt;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    if (fgets(buf, maxlen, stdin) == NULL) {
        buf[0] = '\0';
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    buf[strcspn(buf, "\r\n")] = 0;
}

// Handshake
static int handshake_server(int sock) {
    char buf[BUF_SIZE];

    ssize_t n = read(sock, buf, sizeof(buf)-1);
    if (n <= 0) return 0;
    buf[n] = 0;

    if (strncmp(buf, "CLIENT_HELLO", 12) != 0) {
        printf("[Handshake] Invalid: %s\n", buf);
        return 0;
    }
    sleep(1);
    printf("[Handshake] Received: %s", buf);

    const char *sh = "SERVER_HELLO\n";
    write(sock, sh, strlen(sh));
    printf("[Handshake] Sent: %s", sh);
    sleep(1);

    uint32_t net_ek_len, net_iv_len;
    if (read(sock, &net_ek_len, 4) != 4) return 0;
    if (read(sock, &net_iv_len, 4) != 4) return 0;

    int ek_len = ntohl(net_ek_len);
    int iv_len = ntohl(net_iv_len);

    unsigned char *enc_key = malloc(ek_len);
    unsigned char *enc_iv  = malloc(iv_len);
    if (!enc_key || !enc_iv) return 0;

    if (read(sock, enc_key, ek_len) != ek_len) { free(enc_key); free(enc_iv); return 0; }
    if (read(sock, enc_iv,  iv_len) != iv_len) { free(enc_key); free(enc_iv); return 0; }

    unsigned char dec_key[32];
    unsigned char dec_iv[16];

    int dk_len = rsa_dec(server_priv, enc_key, ek_len, dec_key);
    int di_len = rsa_dec(server_priv, enc_iv,  iv_len, dec_iv);

    free(enc_key);
    free(enc_iv);

    if (dk_len != 32 || di_len != 16) {
        printf("[Handshake] RSA decrypt failed\n");
        return 0;
    }

    memcpy(session_key, dec_key, 32);
    memcpy(session_iv,  dec_iv, 16);

    FILE *log = fopen("session_server.log", "w");
    if (log) {
        fprintf(log, "SESSION KEY: ");
        for (int i=0;i<32;i++) fprintf(log, "%02X", session_key[i]);
        fprintf(log, "\nSESSION IV : ");
        for (int i=0;i<16;i++) fprintf(log, "%02X", session_iv[i]);
        fprintf(log, "\n");
        fclose(log);
    }
    sleep(1);
    printf("[Handshake] Session key & IV saved to session_server.log\n");

    const char *ok = "HANDSHAKE_OK\n";
    write(sock, ok, strlen(ok));
    printf("[Handshake] Sent: %s", ok);

    session = 1;
    return 1;
}

static void *recv_thread(void *arg) {
    int sock = *((int*)arg);
    char buf[BUF_SIZE];

    while (!stopped) {
        ssize_t n = read(sock, buf, sizeof(buf)-1);
        if (n <= 0) break;

        buf[n] = 0;
        buf[strcspn(buf, "\r\n")] = 0;

        if (strlen(buf) == 0) continue;

        if (!session) {
            printf("[Plain] %s\n", buf);
            continue;
        }

        printf("[Encrypted] %s ", buf);
        fflush(stdout);

        pthread_mutex_lock(&decrypt_lock);
        strncpy(last_encrypted_msg, buf, sizeof(last_encrypted_msg)-1);
        last_encrypted_msg[sizeof(last_encrypted_msg)-1] = 0;
        decrypt_pending = 1;
        pthread_mutex_unlock(&decrypt_lock);
    }

    stopped = 1;
    return NULL;
}

static void *io_thread(void *arg) {
    int sock = *((int*)arg);
    char line[BUF_SIZE];

    while (!stopped) {
        int need_decrypt = 0;
        char cipher_full[BUF_SIZE];

        pthread_mutex_lock(&decrypt_lock);
        if (decrypt_pending) {
            decrypt_pending = 0;
            strncpy(cipher_full, last_encrypted_msg, sizeof(cipher_full)-1);
            cipher_full[sizeof(cipher_full)-1] = 0;
            need_decrypt = 1;
        }
        pthread_mutex_unlock(&decrypt_lock);

        if (need_decrypt && session) {
            char *sep = strchr(cipher_full, '|');
            if (!sep) {
                printf("[ERROR] invalid encrypted format (no '|')\n");
                continue;
            }

            *sep = 0;
            char *cipher_hex = cipher_full;
            char *hash_hex   = sep + 1;

            // 키 입력
            printf("Enter AES key (hex 64 chars): ");
            fflush(stdout);

            char key_input[128];
            input_hidden(key_input, sizeof(key_input));
            if (key_input[0] == 0) {
                printf("[INFO] empty key, skip decrypt\n");
                continue;
            }

            unsigned char keybuf[32];
            if (hex_to_bytes(key_input, keybuf) != 32) {
                printf("[ERROR] invalid key length\n");
                continue;
            }

            unsigned char cipher_raw[BUF_SIZE];
            int clen = hex_to_bytes(cipher_hex, cipher_raw);
            if (clen <= 0) {
                printf("[ERROR] invalid cipher hex\n");
                continue;
            }

            // AES 복호화
            unsigned char *plain = NULL;
            int plain_len = 0;
            if (!aes_dec(cipher_raw, clen, keybuf, session_iv,
                         &plain, &plain_len)) {
                printf("[ERROR] decrypt failed (wrong key?)\n");
                free(plain);
                continue;
            }
            plain[plain_len] = 0;

            // SHA-256 무결성 검증
            unsigned char calc_hash[32];
            unsigned char recv_hash[32];

            if (!sha256_hash((unsigned char*)plain, plain_len, calc_hash)) {
                printf("[ERROR] sha256 failed\n");
                free(plain);
                continue;
            }
            if (hex_to_bytes(hash_hex, recv_hash) != 32) {
                printf("[ERROR] invalid hash hex\n");
                free(plain);
                continue;
            }

            if (memcmp(calc_hash, recv_hash, 32) != 0) {
                printf("[WARNING] INTEGRITY FAILED! (Modified message!)\n");
                printf("client?: %s\n", plain);
            } else {
                printf("\n[OK] Integrity Verified.\n");
                plain_msg_count++;
                printf("#%d client: %s\n", plain_msg_count, plain);
            }

            free(plain);
            continue;
        }

            fflush(stdout);
            if (fgets(line, sizeof(line), stdin) == NULL) {
                usleep(10000);
                continue;
            }

            line[strcspn(line, "\r\n")] = 0;

            if (strcmp(line, "q") == 0 || strcmp(line, "/quit") == 0) {
                stopped = 1;
                shutdown(sock, SHUT_WR);
                break;
            }

            if (strlen(line) == 0) {
                continue;
            }

            if (!session) {
                write(sock, line, strlen(line));
                write(sock, "\n", 1);
                continue;
            }

            unsigned char *cipher = NULL;
            int cipher_len = 0;

            if (!aes_enc((unsigned char*)line, (int)strlen(line),
                         session_key, session_iv,
                         &cipher, &cipher_len)) {
                printf("[ERROR] encryption failed\n");
                continue;
            }

            unsigned char hash[32];
            sha256_hash((unsigned char*)line, strlen(line), hash);

            char hex_cipher[cipher_len*2+1];
            char hex_hash[32*2+1];

            to_hex(cipher, cipher_len, hex_cipher);
            to_hex(hash, 32, hex_hash);

            char packet[BUF_SIZE];
            snprintf(packet, sizeof(packet), "%s|%s", hex_cipher, hex_hash);

            write(sock, packet, strlen(packet));
            write(sock, "\n", 1);
        }
    stopped = 1;
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    if (!load_rsa_private("private.pem", &server_priv)) {
        printf("ERROR: private.pem load failed\n");
        return 1;
    }

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(atoi(argv[1]));

    if (bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listen_sock, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Server listening %s...\n", argv[1]);

    int clnt = accept(listen_sock, NULL, NULL);
    if (clnt < 0) {
        perror("accept");
        return 1;
    }
    printf("Client connected.\n");

    if (!handshake_server(clnt)) {
        printf("Handshake failed\n");
        return 1;
    }

    pthread_t th_recv, th_io;
    pthread_create(&th_recv, NULL, recv_thread, &clnt);
    pthread_create(&th_io,   NULL, io_thread,   &clnt);

    pthread_join(th_io, NULL);
    stopped = 1;
    shutdown(clnt, SHUT_RDWR);
    pthread_join(th_recv, NULL);

    RSA_free(server_priv);
    close(clnt);
    close(listen_sock);
    return 0;
}
