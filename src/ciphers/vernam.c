#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vernam.h"

int vernam_encrypt(const char *text, size_t len, const char *key,
                   char *out, size_t out_size)
{
    if (out_size < len * 2 + 1)
        return EXIT_FAILURE;

    for (size_t i = 0; i < len; i++)
    {
        unsigned char r = (unsigned char)text[i] ^ (unsigned char)key[i];
        snprintf(out + i * 2, 3, "%02x", r);
    }
    return EXIT_SUCCESS;
}

int vernam_decrypt(const unsigned char *bytes, size_t len, const char *key,
                   char *out, size_t out_size)
{
    if (out_size < len + 1)
        return EXIT_FAILURE;

    for (size_t i = 0; i < len; i++)
        out[i] = (char)((unsigned char)bytes[i] ^ (unsigned char)key[i]);

    out[len] = '\0';
    return EXIT_SUCCESS;
}

unsigned char *vernam_hex_to_bytes(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return NULL;

    size_t byte_len = hex_len / 2;
    unsigned char *buf = malloc(byte_len);
    if (buf == NULL)
        return NULL;

    for (size_t i = 0; i < byte_len; i++)
    {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
        {
            free(buf);
            return NULL;
        }
        buf[i] = (unsigned char)byte;
    }
    *out_len = byte_len;
    return buf;
}