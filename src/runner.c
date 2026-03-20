#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runner.h"
#include "utils.h"
#include "caesar.h"
#include "vigenere.h"
#include "vernam.h"
#include "constants.h"

int run_caesar(void)
{
    char text[MAX_TEXT_LENGTH];
    char out[MAX_TEXT_LENGTH];

    read_line("  Text: ", text, sizeof(text));

    int shift = 0;
    for (;;)
    {
        shift = read_int("  Shift (1-25): ");
        if (shift >= 1 && shift <= 25)
            break;
        printf("  Shift must be between 1 and 25.\n");
    }

    int choice = read_choice("Encrypt", "Decrypt");
    int status = (choice == 1)
                     ? caesar_encrypt(text, shift, out, sizeof(out))
                     : caesar_decrypt(text, shift, out, sizeof(out));

    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "  Error: text too long.\n");
        return EXIT_FAILURE;
    }

    printf("\n  Result: %s\n", out);
    return EXIT_SUCCESS;
}

int run_vigenere(void)
{
    char text[MAX_TEXT_LENGTH];
    char key[MAX_TEXT_LENGTH];
    char out[MAX_TEXT_LENGTH];

    read_line("  Text: ", text, sizeof(text));
    read_line("  Key: ", key, sizeof(key));

    int choice = read_choice("Encrypt", "Decrypt");
    int status = (choice == 1)
                     ? vigenere_encrypt(text, key, out, sizeof(out))
                     : vigenere_decrypt(text, key, out, sizeof(out));

    if (status != EXIT_SUCCESS)
    {
        fprintf(stderr, "  Error: key must contain only alphabetic characters.\n");
        return EXIT_FAILURE;
    }

    printf("\n  Result: %s\n", out);
    return EXIT_SUCCESS;
}

int run_vernam(void)
{
    char text[MAX_TEXT_LENGTH];
    char key[MAX_TEXT_LENGTH];

    int choice = read_choice("Encrypt", "Decrypt");

    if (choice == 1)
    {
        read_line("  Text: ", text, sizeof(text));
        read_line("  Key: ", key, sizeof(key));

        size_t text_len = strlen(text);
        if (strlen(key) != text_len)
        {
            fprintf(stderr, "  Error: key length must match text length (%zu chars).\n", text_len);
            return EXIT_FAILURE;
        }

        char out[MAX_TEXT_LENGTH * 2 + 1];
        if (vernam_encrypt(text, text_len, key, out, sizeof(out)) != EXIT_SUCCESS)
        {
            fprintf(stderr, "  Error during encryption.\n");
            return EXIT_FAILURE;
        }
        printf("\n  Encrypted (hex): %s\n", out);
    }
    else
    {
        read_line("  Ciphertext (hex): ", text, sizeof(text));
        read_line("  Key: ", key, sizeof(key));

        size_t byte_len;
        unsigned char *bytes = vernam_hex_to_bytes(text, &byte_len);
        if (bytes == NULL)
        {
            fprintf(stderr, "  Error: invalid hex input.\n");
            return EXIT_FAILURE;
        }
        if (byte_len != strlen(key))
        {
            fprintf(stderr, "  Error: key length must match decoded length (%zu bytes).\n", byte_len);
            free(bytes);
            return EXIT_FAILURE;
        }

        char out[MAX_TEXT_LENGTH];
        int status = vernam_decrypt(bytes, byte_len, key, out, sizeof(out));
        free(bytes);

        if (status != EXIT_SUCCESS)
        {
            fprintf(stderr, "  Error during decryption.\n");
            return EXIT_FAILURE;
        }
        printf("\n  Decrypted: %s\n", out);
    }

    return EXIT_SUCCESS;
}