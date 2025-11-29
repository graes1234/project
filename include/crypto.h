#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* RSA *
int load_rsa_private_from_file(const char *path, RSA **rsa_out);
int load_rsa_public_from_pem_buffer(const unsigned char *buf, size_t buflen, RSA **rsa_out);

int rsa_encrypt_with_rsa_pub(RSA *rsa,
                             const unsigned char *in, int inlen,
                             unsigned char *out);

int rsa_decrypt(RSA *rsa,
                const unsigned char *in, int inlen,
                unsigned char *out);
*/
/* AES */
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **ciphertext, int *cipher_len);

int aes_decrypt(const unsigned char *ciphertext, int cipher_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char **plaintext, int *plaintext_len);

/* SHA-256 */
int sha256_hash(const unsigned char *data, size_t datalen,
                unsigned char out_hash[32]);

/* Secure Random */
int generate_random_bytes(unsigned char *buf, int num);

#endif

