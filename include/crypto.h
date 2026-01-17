#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// RSA
int load_rsa_private(const char *path, RSA **rsa_out);
int load_rsa_public(const unsigned char *buf, size_t buflen, RSA **rsa_out);

int rsa_enc(RSA *rsa,
                             const unsigned char *in, int inlen,
                             unsigned char *out);

int rsa_dec(RSA *rsa,
                const unsigned char *in, int inlen,
                unsigned char *out);

// AES
int aes_enc(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **ciphertext, int *cipher_len);

int aes_dec(const unsigned char *ciphertext, int cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len);

// SHA-256
int sha256_hash(const unsigned char *data, size_t datalen,
                unsigned char out_hash[32]);

// Secure Random
int random_bytes(unsigned char *buf, int num);

#endif

