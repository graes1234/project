//SHA-256 무결성 체크 테스트
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto.h"

void print_hex(const unsigned char *buf, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

int main() {
    const char *msg = "this is integrity test";
    unsigned char hash[32];

    // crypto.c 의 sha256_hash() 호출
    if (!sha256_hash((unsigned char*)msg, strlen(msg), hash)) {
        printf("SHA-256 failed!\n");
        return 1;
    }

    printf("Message: %s\nSHA256: ", msg);
    print_hex(hash, 32);

    return 0;
}

