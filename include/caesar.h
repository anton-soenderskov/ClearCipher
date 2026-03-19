#ifndef CAESAR_H
#define CAESAR_H

#define MAX_TEXT_LENGTH 1000

int start_caesar(void);
int caesar_encrypt(char *text, int shift);
int caesar_decrypt(char *text, int shift);

#endif