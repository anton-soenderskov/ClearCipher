/*
 * This file contains the implementation of the Caesar cipher.
 * The Caesar cipher is a simple substitution cipher that shifts each letter in the plaintext by a fixed number of positions down the alphabet.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "caesar.h"
#include "constants.h"

int start_caesar(void)
{
    char text[MAX_TEXT_LENGTH];
    int shift;

    printf("Enter the text to encrypt/decrypt: ");
    fgets(text, MAX_TEXT_LENGTH, stdin);
    text[strcspn(text, "\n")] = '\0';

    printf("Enter the shift value (1-25): ");
    scanf("%d", &shift);
    if (shift < 1 || shift > 25)
    {
        fprintf(stderr, "Invalid shift value. Please enter a number between 1 and 25.\n");
        return EXIT_FAILURE;
    }

    printf("Choose an option:\n");
    printf("1. Encrypt\n");
    printf("2. Decrypt\n");
    int choice;
    scanf("%d", &choice);

    if (choice == 1)
    {
        return caesar_encrypt(text, shift);
    }
    else if (choice == 2)
    {
        return caesar_decrypt(text, shift);
    }
    else
    {
        fprintf(stderr, "Invalid choice. Please enter 1 or 2.\n");
        return EXIT_FAILURE;
    }
}

int caesar_encrypt(char *text, int shift)
{
    printf("Encrypting text: %s with shift: %d\n", text, shift);
    char *encrypted_text = calloc(strlen(text) + 1, sizeof(char));
    if (encrypted_text == NULL)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }
    for (size_t i = 0; i < strlen(text); i++)
    {
        char c = text[i];
        char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)c));
        if (found != NULL)
        {
            size_t index = found - VALID_CHARACTERS;
            size_t new_index = (index + shift) % 26;
            encrypted_text[i] = VALID_CHARACTERS[new_index];
            printf("  - %c shifts to %c\n", VALID_CHARACTERS[index], encrypted_text[i]);
        }
        else
        {
            encrypted_text[i] = c;
            printf("  - '%c' is a non-alphabet character and will be perserved\n", c);
        }
    }
    printf("Encrypted text: %s\n", encrypted_text);
    free(encrypted_text);
    return EXIT_SUCCESS;
}

int caesar_decrypt(char *text, int shift)
{
    printf("Decrypting text: %s with shift: %d\n", text, shift);
    char *decrypted_text = calloc(strlen(text) + 1, sizeof(char));
    if (decrypted_text == NULL)
    {
        perror("calloc");
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < strlen(text); i++)
    {
        char c = text[i];
        char *found = strchr(VALID_CHARACTERS, c);
        if (found != NULL)
        {
            size_t index = found - VALID_CHARACTERS;
            size_t new_index = (index - shift + 26) % 26;
            decrypted_text[i] = VALID_CHARACTERS[new_index];
            printf("  - %c shifts to %c\n", VALID_CHARACTERS[index], decrypted_text[i]);
        }
        else
        {
            decrypted_text[i] = c;
            printf("  - '%c' is a non-alphabet character and will be perserved\n", c);
        }
    }

    printf("Decrypted text: %s\n", decrypted_text);
    free(decrypted_text);
    return EXIT_SUCCESS;
}