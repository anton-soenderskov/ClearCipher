#include <string.h>

#include "common.h"
#include "cipher_parser.h"
#include "caesar.h"
#include "vigenere.h"

int parse_cipher(const char *arg)
{
    if (arg == NULL)
    {
        return STATUS_ERROR;
    }

    if (strcmp(arg, "caesar") == 0)
    {
        if (start_caesar() == 0)
        {
            return STATUS_SUCCESS;
        }
        return STATUS_ERROR;
    }
    else if (strcmp(arg, "vigenere") == 0)
    {
        if (start_vigenere() == 0)
        {
            return STATUS_SUCCESS;
        }
        return STATUS_ERROR;
    }
    else if (strcmp(arg, "vernam") == 0)
    {
        return STATUS_SUCCESS;
    }

    return STATUS_ERROR;
}