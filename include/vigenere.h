#ifndef VIGENERE_H
#define VIGENERE_H

#define MAX_TEXT_LENGTH 1000

int start_vigenere(void);
int vigenere_encrypt(char *text, char *key);
int vigenere_decrypt(char *text, char *key);

#endif