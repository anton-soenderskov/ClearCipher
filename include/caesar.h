#ifndef CAESAR_H
#define CAESAR_H

#include <stddef.h>

int caesar_encrypt(const char *text, int shift, char *out, size_t out_size);
int caesar_decrypt(const char *text, int shift, char *out, size_t out_size);

#endif /* CAESAR_H */