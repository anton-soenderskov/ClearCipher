#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "vigenere.h"
#include "constants.h"

int vigenere_encrypt(const char *text, const char *key, char *out, size_t out_size)
{
    size_t text_len = strlen(text);
    size_t key_len = strlen(key);

    if (key_len == 0 || text_len >= out_size)
        return EXIT_FAILURE;

    size_t key_pos = 0;

    for (size_t i = 0; i < text_len; i++)
    {
        const char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)text[i]));
        if (found != NULL)
        {
            size_t key_index = key_pos % key_len;
            const char *key_found = strchr(VALID_CHARACTERS, tolower((unsigned char)key[key_index]));
            if (key_found == NULL)
                return EXIT_FAILURE;

            size_t index = (size_t)(found - VALID_CHARACTERS);
            size_t shift = (size_t)(key_found - VALID_CHARACTERS);
            out[i] = VALID_CHARACTERS[(index + shift) % 26];
            key_pos++;
        }
        else
        {
            out[i] = text[i];
        }
    }
    out[text_len] = '\0';
    return EXIT_SUCCESS;
}

int vigenere_decrypt(const char *text, const char *key, char *out, size_t out_size)
{
    size_t text_len = strlen(text);
    size_t key_len = strlen(key);

    if (key_len == 0 || text_len >= out_size)
        return EXIT_FAILURE;

    size_t key_pos = 0;

    for (size_t i = 0; i < text_len; i++)
    {
        const char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)text[i]));
        if (found != NULL)
        {
            size_t key_index = key_pos % key_len;
            const char *key_found = strchr(VALID_CHARACTERS, tolower((unsigned char)key[key_index]));
            if (key_found == NULL)
                return EXIT_FAILURE;

            size_t index = (size_t)(found - VALID_CHARACTERS);
            size_t shift = (size_t)(key_found - VALID_CHARACTERS);
            out[i] = VALID_CHARACTERS[(index + 26 - shift) % 26];
            key_pos++;
        }
        else
        {
            out[i] = text[i];
        }
    }
    out[text_len] = '\0';
    return EXIT_SUCCESS;
}