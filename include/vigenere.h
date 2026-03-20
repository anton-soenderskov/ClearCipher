#ifndef VIGENERE_H
#define VIGENERE_H

#include <stddef.h>

int vigenere_encrypt(const char *text, const char *key, char *out, size_t out_size);
int vigenere_decrypt(const char *text, const char *key, char *out, size_t out_size);

#endif /* VIGENERE_H */