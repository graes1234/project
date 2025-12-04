//AES-256-CBC 암/복호화 단독 테스트
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"

int main() {
    unsigned char key[32] = "01234567890123456789012345678901"; // 32 bytes
    unsigned char iv[16]  = "0123456789012345";                 // 16 bytes

    unsigned char plaintext[] = "hello! 이것은 AES 테스트입니다.";

    unsigned char *cipher = NULL;
    unsigned char *decrypted = NULL;
    int cipher_len = 0;
    int dec_len = 0;

    printf("Plaintext: %s\n", plaintext);

    /* AES Encrypt */
    if (!aes_encrypt(plaintext, strlen((char*)plaintext),
                     key, iv, &cipher, &cipher_len)) {
        printf("Encryption failed!\n");
        return 1;
    }

    printf("\nCiphertext (%d bytes):\n", cipher_len);
    for (int i = 0; i < cipher_len; i++)
        printf("%02X ", cipher[i]);
    printf("\n");

    /* AES Decrypt */
    if (!aes_decrypt(cipher, cipher_len,
                     key, iv, &decrypted, &dec_len)) {
        printf("Decryption failed!\n");
        free(cipher);
        return 1;
    }

    decrypted[dec_len] = '\0';

    printf("\nDecrypted (%d bytes): %s\n", dec_len, decrypted);

    free(cipher);
    free(decrypted);

    return 0;
}
