#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "common.h"
#include "cipher_parser.h"

static void print_help(const char *prog_name)
{
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  -h             Show this help message\n");
    printf("  -l             List available ciphers\n");
    printf("  -s <cipher>    Try a cipher\n");
    printf("  -r <cipher>    Read about a cipher\n");
}

static void list_ciphers(void)
{
    printf("Available ciphers:\n");
    printf("  - Caesar Cipher\n");
    printf("  - Vigenère Cipher\n");
    printf("  - Vernam Cipher (One-Time Pad)\n");
}

int main(int argc, char *argv[])
{

    if (argc == 1)
    {
        print_help(argv[0]);
        return STATUS_SUCCESS;
    }

    int status = 0;
    int opt;
    bool h_set = false;
    bool l_set = false;
    bool s_set = false;
    bool r_set = false;
    while ((opt = getopt(argc, argv, "hls:r:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            h_set = true;
            break;
        case 'l':
            l_set = true;
            break;
        case 's':
            s_set = true;
            break;
        case 'r':
            r_set = true;
            break;
        default:
            break;
        }
    }

    if (h_set)
    {
        print_help(argv[0]);
    }

    if (l_set)
    {
        list_ciphers();
    }

    if (s_set)
    {
        status = parse_cipher(optarg);
        if (status == 1)
        {
            return STATUS_ERROR;
        }
    }

    return STATUS_SUCCESS;
}