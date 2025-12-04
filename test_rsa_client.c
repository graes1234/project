#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include "crypto.h"

/* 헥스 출력 함수 */
void print_hex(const unsigned char *buf, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    RSA *server_pub = NULL;
    RSA *server_priv = NULL;

    /* 1) 서버 공개키 로드 (public.pem) */
    FILE *f = fopen("public.pem", "rb");
    if (!f) {
        printf("public.pem open failed\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long pub_sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *pub_buf = malloc(pub_sz);
    fread(pub_buf, 1, pub_sz, f);
    fclose(f);

    if (!load_rsa_public_from_pem_buffer(pub_buf, pub_sz, &server_pub)) {
        printf("load_rsa_public_from_pem_buffer FAILED\n");
        return 1;
    }

    /* 2) 서버 개인키 로드 */
    if (!load_rsa_private_from_file("private.pem", &server_priv)) {
        printf("load_rsa_private_from_file FAILED\n");
        return 1;
    }

    /* ─────────────────────────────────────────
       CLIENT SIDE (세션키 생성하는 쪽)
       ───────────────────────────────────────── */
    unsigned char aes_key[32];
    unsigned char aes_iv[16];

    RAND_bytes(aes_key, 32);   // 클라이언트가 키 생성
    RAND_bytes(aes_iv, 16);

    printf("CLIENT GENERATED AES KEY:\n");
    print_hex(aes_key, 32);

    printf("CLIENT GENERATED AES IV:\n");
    print_hex(aes_iv, 16);

    /* 3) 클라이언트가 서버 공개키로 암호화 */
    unsigned char encrypted_key[256];
    int enc_len = rsa_encrypt_with_rsa_pub(server_pub, aes_key, 32, encrypted_key);

    if (enc_len == -1) {
        printf("RSA encryption failed\n");
        return 1;
    }

    printf("\nEncrypted key length: %d\n", enc_len);

    /* ─────────────────────────────────────────
       SERVER SIDE (개인키로 복호화하는 쪽)
       ───────────────────────────────────────── */
    unsigned char decrypted_key[256];
    int dec_len = rsa_decrypt(server_priv, encrypted_key, enc_len, decrypted_key);

    if (dec_len == -1) {
        printf("RSA decryption failed\n");
        return 1;
    }

    printf("\nSERVER RECOVERED AES KEY:\n");
    print_hex(decrypted_key, dec_len);

    /* 4) 검증 */
    if (dec_len == 32 && memcmp(aes_key, decrypted_key, 32) == 0)
        printf("\n✔ RSA SESSION KEY EXCHANGE SUCCESS!\n");
    else
        printf("\n❌ RSA SESSION KEY MISMATCH!\n");

    return 0;
}
