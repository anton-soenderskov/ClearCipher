#ifndef DES_H
#define DES_H

#include <stddef.h>
#include <stdint.h>

int des_encrypt(const char *text, uint8_t *out, size_t out_size);
int des_decrypt(const uint8_t *ciphertext, size_t cipher_len, uint64_t key64, char *out, size_t out_size);

#endif /* DES_H */