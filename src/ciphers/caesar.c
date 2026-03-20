#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "caesar.h"
#include "constants.h"

int caesar_encrypt(const char *text, int shift, char *out, size_t out_size)
{
    size_t len = strlen(text);
    if (len >= out_size)
        return EXIT_FAILURE;

    for (size_t i = 0; i < len; i++)
    {
        const char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)text[i]));
        if (found != NULL)
        {
            size_t index = (size_t)(found - VALID_CHARACTERS);
            size_t new_index = (index + (size_t)shift) % 26;
            out[i] = VALID_CHARACTERS[new_index];
        }
        else
        {
            out[i] = text[i];
        }
    }
    out[len] = '\0';
    return EXIT_SUCCESS;
}

int caesar_decrypt(const char *text, int shift, char *out, size_t out_size)
{
    size_t len = strlen(text);
    if (len >= out_size)
        return EXIT_FAILURE;

    for (size_t i = 0; i < len; i++)
    {
        const char *found = strchr(VALID_CHARACTERS, tolower((unsigned char)text[i]));
        if (found != NULL)
        {
            size_t index = (size_t)(found - VALID_CHARACTERS);
            size_t new_index = (index + 26 - (size_t)shift) % 26;
            out[i] = VALID_CHARACTERS[new_index];
        }
        else
        {
            out[i] = text[i];
        }
    }
    out[len] = '\0';
    return EXIT_SUCCESS;
}