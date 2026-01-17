#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// RSA 구조체 로드
int load_rsa_private(const char *path, RSA **rsa_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    RSA *rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    if (!rsa) return 0;
    *rsa_out = rsa;
    return 1;
}

// RSA 공개키 로드
int load_rsa_public(const unsigned char *buf, size_t buflen, RSA **rsa_out) {
    BIO *bio = BIO_new_mem_buf((void*)buf, (int)buflen);
    if (!bio) return 0;

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsa) return 0;
    *rsa_out = rsa;
    return 1;
}

// RSA 공개키로 암호화
int rsa_enc(RSA *rsa, const unsigned char *in, int inlen, unsigned char *out) {
    if (!rsa) return -1;
    return RSA_public_encrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
}

// RSA 개인키로 복호화
int rsa_dec(RSA *rsa, const unsigned char *in, int inlen, unsigned char *out) {
    if (!rsa) return -1;
    return RSA_private_decrypt(inlen, in, out, rsa, RSA_PKCS1_OAEP_PADDING);
}

// AES 암호화
int aes_enc(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **ciphertext, int *cipher_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //컨텍스트 생성
    if (!ctx) return 0;
    int len;
    int ciphertext_len;
    /* 암호문 저장 공간 확보 */
    *ciphertext = (unsigned char *)malloc(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!*ciphertext) { EVP_CIPHER_CTX_free(ctx); return 0; }

    /* 암호화 연산 초기화 */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx); free(*ciphertext); return 0;
    }

    /* 데이터 암호화 */
    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx); free(*ciphertext); return 0;
    }
    ciphertext_len = len;

    /* 암호화 종료 */
    if (1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); free(*ciphertext); return 0;
    }
    ciphertext_len += len;
    *cipher_len = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// AES 복호화
int aes_dec(const unsigned char *ciphertext, int cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //컨텍스트 생성
    if (!ctx) return 0;
    int len;
    int plaintext_length;
    /* 평문 저장 공간 확보 */
    *plaintext = (unsigned char *)malloc(cipher_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!*plaintext) { EVP_CIPHER_CTX_free(ctx); return 0; }

    /* 복호화 연산 초기화 */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx); free(*plaintext); return 0;
    }

    /* 데이터 복호화 */
    if (1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, cipher_len)) {
        EVP_CIPHER_CTX_free(ctx); free(*plaintext); return 0;
    }
    plaintext_length = len;

    /* 복호화 종료 */
    if (1 != EVP_DecryptFinal_ex(ctx, *plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx); free(*plaintext); return 0;
    }
    plaintext_length += len;
    *plaintext_len = plaintext_length;
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// sha256
int sha256_hash(const unsigned char *data, size_t datalen, unsigned char out_hash[32]) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); //컨텍스트 생성
    if (!mdctx) return 0;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) { EVP_MD_CTX_free(mdctx); return 0; }
    if (1 != EVP_DigestUpdate(mdctx, data, datalen)) { EVP_MD_CTX_free(mdctx); return 0; }

    unsigned int outlen = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, out_hash, &outlen)) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    return 1;
}

int random_bytes(unsigned char *buf, int num) {
    return RAND_bytes(buf, num) == 1;
}

