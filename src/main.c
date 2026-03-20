#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "common.h"
#include "runner.h"
#include "ui.h"

static void print_help(const char *prog_name)
{
    printf("Usage: %s [options]\n\n", prog_name);
    printf("  -h             Show this help message\n");
    printf("  -l             List available ciphers\n");
    printf("  -s <cipher>    Run a cipher directly\n");
    printf("  (none)         Launch interactive TUI\n");
}

static void list_ciphers(void)
{
    printf("Available ciphers:\n");
    printf("  caesar    Caesar Cipher\n");
    printf("  vigenere  Vigenere Cipher\n");
    printf("  vernam    Vernam Cipher (One-Time Pad)\n");
}

static int run_cipher_by_name(const char *name)
{
    if (strcmp(name, "caesar") == 0)
        return run_caesar();
    if (strcmp(name, "vigenere") == 0)
        return run_vigenere();
    if (strcmp(name, "vernam") == 0)
        return run_vernam();
    fprintf(stderr, "Unknown cipher: %s\n", name);
    return STATUS_ERROR;
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        run_ui();
        return STATUS_SUCCESS;
    }

    int opt;
    bool h_set = false;
    bool l_set = false;
    bool s_set = false;

    while ((opt = getopt(argc, argv, "hls:")) != -1)
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
        default:
            break;
        }
    }

    if (h_set)
        print_help(argv[0]);
    if (l_set)
        list_ciphers();
    if (s_set)
        return run_cipher_by_name(optarg);

    return STATUS_SUCCESS;
}