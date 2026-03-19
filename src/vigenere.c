/*
 * This file contains the implementation of the Vigenere cipher.
 * The Vigenere cipher is a method of encrypting alphabetic text by using a simple form of polyalphabetic substitution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "vigenere.h"
#include "constants.h"

int start_vigenere(void)
{
    printf("Enter the text to encrypt/decrypt: ");
    char text[MAX_TEXT_LENGTH];
    fgets(text, MAX_TEXT_LENGTH, stdin);
    text[strcspn(text, "\n")] = '\0';

    printf("Enter the key (e.g., banana): ");
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
        return vigenere_encrypt(text, key);
    }
    else if (choice == 2)
    {
        return vigenere_decrypt(text, key);
    }
    else
    {
        fprintf(stderr, "Invalid choice. Please enter 1 or 2.\n");
        return EXIT_FAILURE;
    }
}

int vigenere_encrypt(char *text, char *key)
{
    printf("Encrypting text: %s with key: %s\n", text, key);

    size_t text_len = strlen(text);
    size_t key_len = strlen(key);
    if (key_len == 0)
    {
        fprintf(stderr, "Key cannot be empty.\n");
        return EXIT_FAILURE;
    }

    char *encrypted_text = calloc(text_len + 1, sizeof(char));
    if (encrypted_text == NULL)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }

    size_t key_pos = 0;

    for (size_t i = 0; i < text_len; i++)
    {
        char c = text[i];
        const char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)c));

        if (found != NULL)
        {
            size_t key_index = key_pos % key_len;
            const char *key_found = strchr(VALID_CHARACTERS, tolower((unsigned char)key[key_index]));
            if (key_found == NULL)
            {
                printf("Key must contain only alphabetic characters.\n");
                free(encrypted_text);
                return EXIT_FAILURE;
            }

            size_t index = (size_t)(found - VALID_CHARACTERS);
            size_t shift = (size_t)(key_found - VALID_CHARACTERS);
            size_t new_index = (index + shift) % 26;

            encrypted_text[i] = VALID_CHARACTERS[new_index];
            printf("  - %c shifts to %c using key character %c: because (%zu + %zu) %% 26 = %zu\n",
                   VALID_CHARACTERS[index], encrypted_text[i], key[key_index], index, shift, new_index);
            key_pos++;
        }
        else
        {
            encrypted_text[i] = c;
            printf("  - '%c' is a non-alphabet character and will be preserved\n", c);
        }
    }

    printf("Encrypted text: %s\n", encrypted_text);
    free(encrypted_text);
    return EXIT_SUCCESS;
}

int vigenere_decrypt(char *text, char *key)
{
    printf("Decrypting text: %s with key: %s\n", text, key);

    size_t text_len = strlen(text);
    size_t key_len = strlen(key);
    if (key_len == 0)
    {
        fprintf(stderr, "Key cannot be empty.\n");
        return EXIT_FAILURE;
    }

    char *decrypted_text = calloc(text_len + 1, sizeof(char));
    if (decrypted_text == NULL)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }

    size_t key_pos = 0;

    for (size_t i = 0; i < text_len; i++)
    {
        char c = text[i];
        const char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)c));

        if (found != NULL)
        {
            size_t key_index = key_pos % key_len;
            const char *key_found = strchr(VALID_CHARACTERS, tolower((unsigned char)key[key_index]));
            if (key_found == NULL)
            {
                fprintf(stderr, "Key must contain only alphabetic characters.\n");
                free(decrypted_text);
                return EXIT_FAILURE;
            }

            size_t index = (size_t)(found - VALID_CHARACTERS);
            size_t shift = (size_t)(key_found - VALID_CHARACTERS);
            size_t new_index = (index + 26 - shift) % 26;

            decrypted_text[i] = VALID_CHARACTERS[new_index];
            printf("  - %c shifts to %c using key character %c: because (%zu + 26 - %zu) %% 26 = %zu\n",
                   VALID_CHARACTERS[index], decrypted_text[i], key[key_index], index, shift, new_index);
            key_pos++;
        }
        else
        {
            decrypted_text[i] = c;
            printf("  - '%c' is a non-alphabet character and will be preserved\n", c);
        }
    }

    printf("Decrypted text: %s\n", decrypted_text);
    free(decrypted_text);
    return EXIT_SUCCESS;
}