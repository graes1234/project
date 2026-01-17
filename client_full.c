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
#include <fcntl.h>

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
static int handshake_client(int sock) {
    char buf[BUF_SIZE];

    const char *ch = "CLIENT_HELLO\n";
    write(sock, ch, strlen(ch));
    printf("[Handshake] Sent: %s", ch);
    sleep(1);

    ssize_t n = read(sock, buf, sizeof(buf)-1);
    if (n <= 0) return 0;
    buf[n] = 0;

    if (strncmp(buf, "SERVER_HELLO", 12) != 0) {
        printf("[Handshake] Invalid response: %s\n", buf);
        return 0;
    }
    sleep(1);
    printf("[Handshake] Received: %s", buf);

    if (!random_bytes(session_key, 32) ||
        !random_bytes(session_iv, 16)) {
        printf("[Handshake] random_bytes failed\n");
        return 0;
    }
    printf("[Handshake] Client generated AES KEY/IV\n");
    sleep(1);

    FILE *f = fopen("public.pem", "rb");
    if (!f) {
        printf("[Handshake] public.pem open failed\n");
        return 0;
    }
    fseek(f, 0, SEEK_END);
    long pub_sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *pubbuf = (unsigned char*)malloc(pub_sz);
    if (!pubbuf) { fclose(f); return 0; }
    fread(pubbuf, 1, pub_sz, f);
    fclose(f);

    RSA *server_pub = NULL;
    if (!load_rsa_public(pubbuf, pub_sz, &server_pub)) {
        printf("[Handshake] load_rsa_public failed\n");
        free(pubbuf);
        return 0;
    }
    free(pubbuf);

    unsigned char enc_key[256];
    unsigned char enc_iv[256];

    int ek_len = rsa_enc(server_pub, session_key, 32, enc_key);
    int iv_len = rsa_enc(server_pub, session_iv, 16, enc_iv);
    RSA_free(server_pub);

    if (ek_len < 0 || iv_len < 0) {
        printf("[Handshake] RSA encryption failed\n");
        return 0;
    }

    uint32_t net_ek_len = htonl(ek_len);
    uint32_t net_iv_len = htonl(iv_len);

    write(sock, &net_ek_len, 4);
    write(sock, &net_iv_len, 4);
    write(sock, enc_key, ek_len);
    write(sock, enc_iv, iv_len);

    sleep(1);
    printf("[Handshake] Sent encrypted AES KEY/IV\n");

    FILE *log = fopen("session_client.log", "w");
    if (log) {
        fprintf(log, "SESSION KEY: ");
        for (int i=0;i<32;i++) fprintf(log, "%02X", session_key[i]);
        fprintf(log, "\nSESSION IV : ");
        for (int i=0;i<16;i++) fprintf(log, "%02X", session_iv[i]);
        fprintf(log, "\n");
        fclose(log);
        printf("[Handshake] Session key & IV saved to session_client.log\n");
    }

    n = read(sock, buf, sizeof(buf)-1);
    if (n <= 0) {
        printf("[Handshake] Failed reading HANDSHAKE_OK\n");
        return 0;
    }
    buf[n] = 0;

    if (strncmp(buf, "HANDSHAKE_OK", 12) != 0) {
        printf("[Handshake] Invalid final msg: %s\n", buf);
        return 0;
    }
    sleep(1);
    printf("[Handshake] Received: %s", buf);
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
        if (strlen(buf) == 0) continue;//

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
                printf("server?: %s\n", plain);
            } else {
                printf("\n[OK] Integrity Verified.\n");
                plain_msg_count++;
                printf("#%d server: %s\n", plain_msg_count, plain);
            }

            free(plain);
            continue;
        }

        fflush(stdout);
        if (fgets(line, sizeof(line), stdin) == NULL) {
            usleep(10000);
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
    if (argc != 3) {
        printf("Usage: %s <ip> <port>\n", argv[0]);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    printf("Connected.\n");

    if (!handshake_client(sock)) {
        printf("Handshake failed\n");
        return 1;
    }

    pthread_t th_recv, th_io;
    pthread_create(&th_recv, NULL, recv_thread, &sock);
    pthread_create(&th_io,   NULL, io_thread,   &sock);

    pthread_join(th_io, NULL);
    stopped = 1;
    shutdown(sock, SHUT_RDWR);
    pthread_join(th_recv, NULL);

    close(sock);
    return 0;
}

