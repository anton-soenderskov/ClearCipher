#include <stdio.h>
#include <stdlib.h>

#include "ui.h"
#include "runner.h"

/* ── Platform: raw key input ─────────────────────────────────────────────── */
#ifdef _WIN32
#include <conio.h>
#include <windows.h>

static void term_raw(void) { /* _getch() is already raw */ }
static void term_restore(void) { /* nothing needed */ }

static int read_key(void)
{
    int c = _getch();
    if (c == 0 || c == 0xE0)
    {
        int c2 = _getch();
        if (c2 == 72)
            return 'A';
        if (c2 == 80)
            return 'B';
        return 0;
    }
    return c;
}

static void clear_screen(void) { system("cls"); }
static void flush_input(void)
{
    while (_kbhit())
        _getch();
}

#else
#include <termios.h>
#include <unistd.h>

static struct termios orig_termios;

static void term_restore(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

static void term_raw(void)
{
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(term_restore);

    struct termios raw = orig_termios;
    raw.c_lflag &= ~(unsigned)(ECHO | ICANON);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static int read_key(void)
{
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) != 1)
        return 0;

    if (c == 0x1B)
    {
        unsigned char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1)
            return 0x1B;
        if (read(STDIN_FILENO, &seq[1], 1) != 1)
            return 0x1B;
        if (seq[0] == '[')
        {
            if (seq[1] == 'A')
                return 'A';
            if (seq[1] == 'B')
                return 'B';
        }
        return 0x1B;
    }
    return (int)c;
}

static void clear_screen(void) { printf("\033[3J\033[2J\033[H"); }
static void flush_input(void) { tcflush(STDIN_FILENO, TCIFLUSH); }

#endif /* _WIN32 */

/* ── Layout ──────────────────────────────────────────────────────────────── */
#define RULE "  ────────────────────────────────────────"
#define PADDING "  "

/* ── Menu ────────────────────────────────────────────────────────────────── */
static const char *MENU_ITEMS[] = {
    "Caesar Cipher",
    "Vigenere Cipher",
    "Vernam Cipher (One-Time Pad)",
    "Data Encryption Standard (DES)",
    "Quit",
};
#define MENU_COUNT 5

/* Runner functions indexed to match MENU_ITEMS */
typedef int (*cipher_runner_fn)(void);
static const cipher_runner_fn RUNNERS[] = {
    run_caesar,
    run_vigenere,
    run_vernam,
    run_des,
};

/* ── Rendering ───────────────────────────────────────────────────────────── */
static void draw(int selected)
{
    clear_screen();
    printf("\n");
    printf(PADDING "ClearCipher\n");
    printf(RULE "\n\n");

    for (int i = 0; i < MENU_COUNT; i++)
    {
        if (i == selected)
            printf(PADDING " » %s\n", MENU_ITEMS[i]);
        else
            printf(PADDING "   %s\n", MENU_ITEMS[i]);
    }

    printf("\n" RULE "\n");
    printf(PADDING "↑↓ navigate   Enter select   q quit\n");
}

/* ── Cipher screen ───────────────────────────────────────────────────────── */
static void run_cipher(int index)
{
    term_restore();
    clear_screen();

    printf("\n");
    printf(PADDING "%s\n", MENU_ITEMS[index]);
    printf(RULE "\n\n");

    RUNNERS[index]();

    printf("\n" RULE "\n");
    printf(PADDING "Press Enter to return");
    fflush(stdout);

    term_raw();
    flush_input();

    int key;
    do
    {
        key = read_key();
    } while (key != '\n' && key != '\r');
}

/* ── Main event loop ─────────────────────────────────────────────────────── */
void run_ui(void)
{
    term_raw();
    int selected = 0;

    for (;;)
    {
        draw(selected);
        int key = read_key();

        if (key == 'A' || key == 'k')
            selected = (selected - 1 + MENU_COUNT) % MENU_COUNT;
        else if (key == 'B' || key == 'j')
            selected = (selected + 1) % MENU_COUNT;
        else if (key == '\r' || key == '\n')
        {
            if (selected == MENU_COUNT - 1)
                break;
            run_cipher(selected);
        }
        else if (key == 'q' || key == 'Q')
            break;
    }

    term_restore();
    clear_screen();
}