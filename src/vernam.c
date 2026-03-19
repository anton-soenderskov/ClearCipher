/*
 * This file contains the implementation of the Vernam cipher.
 * The Vernam cipher is also called the one-time pad and is a method of encrypting alphabetic text by using a simple form of polyalphabetic substitution.
 * It is considered unbreakable when used with a truly random key that is as long as the plaintext and is never reused.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "vernam.h"
#include "constants.h"

static char display_char(unsigned char c)
{
    return isprint(c) ? (char)c : '.';
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
    {
        return NULL;
    }
    size_t byte_len = hex_len / 2;
    unsigned char *bytes = malloc(byte_len);
    if (bytes == NULL)
    {
        return NULL;
    }
    for (size_t i = 0; i < byte_len; i++)
    {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
        {
            free(bytes);
            return NULL;
        }
        bytes[i] = (unsigned char)byte;
    }
    *out_len = byte_len;
    return bytes;
}

int start_vernam(void)
{
    printf("Enter the text to encrypt/decrypt: ");
    char text[MAX_TEXT_LENGTH];
    fgets(text, MAX_TEXT_LENGTH, stdin);
    text[strcspn(text, "\n")] = '\0';

    printf("Enter the key (must be the same length as the text): ");
    char key[MAX_TEXT_LENGTH];
    fgets(key, MAX_TEXT_LENGTH, stdin);
    key[strcspn(key, "\n")] = '\0';

    printf("Choose an option:\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");

    int choice;
    scanf("%d", &choice);

    if (choice == 1)
    {
        if (strlen(key) != strlen(text))
        {
            fprintf(stderr, "Key must be the same length as the text.\n");
            return EXIT_FAILURE;
        }
        return vernam_cipher(text, strlen(text), key, "encrypt");
    }
    else if (choice == 2)
    {
        size_t byte_len;
        unsigned char *bytes = hex_to_bytes(text, &byte_len);
        if (bytes == NULL)
        {
            fprintf(stderr, "Invalid hex input for decryption.\n");
            return EXIT_FAILURE;
        }
        if (byte_len != strlen(key))
        {
            fprintf(stderr, "Key must be the same length as the decoded ciphertext (%zu bytes).\n", byte_len);
            free(bytes);
            return EXIT_FAILURE;
        }
        int ret = vernam_cipher((char *)bytes, byte_len, key, "decrypt");
        free(bytes);
        return ret;
    }
    else
    {
        fprintf(stderr, "Invalid choice. Please enter 1 or 2.\n");
        return EXIT_FAILURE;
    }
}

int vernam_cipher(char *text, size_t len, char *key, char *option)
{
    char *result = calloc(len + 1, sizeof(char));
    if (result == NULL)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }
    for (size_t i = 0; i < len; i++)
    {
        unsigned char t = (unsigned char)text[i];
        unsigned char k = (unsigned char)key[i];
        unsigned char r = t ^ k;

        result[i] = (char)r;

        printf("  - '%c' (0x%02X) XOR '%c' (0x%02X) = '%c' (0x%02X)\n",
               display_char(t), t,
               display_char(k), k,
               display_char(r), r);
    }
    if (strcmp(option, "encrypt") == 0)
    {
        printf("Encrypted text (hex): ");
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x", (unsigned char)result[i]);
        }
        printf("\n");
    }
    else if (strcmp(option, "decrypt") == 0)
    {
        printf("Decrypted text: %s\n", result);
    }
    free(result);
    return EXIT_SUCCESS;
}