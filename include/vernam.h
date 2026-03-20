#ifndef VERNAM_H
#define VERNAM_H

#include <stddef.h>

int vernam_encrypt(const char *text, size_t len, const char *key,
                   char *out, size_t out_size);
int vernam_decrypt(const unsigned char *bytes, size_t len, const char *key,
                   char *out, size_t out_size);
unsigned char *vernam_hex_to_bytes(const char *hex, size_t *out_len);

#endif /* VERNAM_H */