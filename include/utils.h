#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

char *read_line(const char *prompt, char *buf, size_t buf_size);
int read_int(const char *prompt);
int read_choice(const char *option_a, const char *option_b);

#endif /* UTILS_H */