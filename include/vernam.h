#ifndef VERNAM_H
#define VERNAM_H

#define MAX_TEXT_LENGTH 1000

#include <ctype.h>

int start_vernam(void);
int vernam_cipher(char *text, size_t len, char *key, char *option);

#endif