#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

char *read_line(const char *prompt, char *buf, size_t buf_size)
{
    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buf, (int)buf_size, stdin) == NULL)
        return NULL;

    buf[strcspn(buf, "\n")] = '\0';
    return buf;
}

int read_int(const char *prompt)
{
    char buf[64];
    for (;;)
    {
        printf("%s", prompt);
        fflush(stdout);

        if (fgets(buf, sizeof(buf), stdin) == NULL)
            continue;

        char *end;
        long val = strtol(buf, &end, 10);
        /* end must advance past at least one digit and hit only whitespace */
        if (end != buf && (*end == '\n' || *end == '\0'))
            return (int)val;

        printf("  Invalid input — please enter a number.\n");
    }
}

int read_choice(const char *option_a, const char *option_b)
{
    printf("  1. %s\n", option_a);
    printf("  2. %s\n", option_b);

    for (;;)
    {
        int v = read_int("  Choice: ");
        if (v == 1 || v == 2)
            return v;
        printf("  Please enter 1 or 2.\n");
    }
}