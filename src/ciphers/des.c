#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(_WIN32)
#include <bcrypt.h>
#endif

#include "des.h"

/*
 * Based on FIPS PUB 46-3:
 * https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
 *
 * DES operates on 64-bit (8-byte) blocks with a 64-bit key (56 bits effective,
 * 8 bits are parity). The algorithm consists of:
 *   1. Key schedule   - derive 16 x 48-bit subkeys from the 64-bit key
 *   2. Initial Permutation (IP)
 *   3. 16 Feistel rounds, each using the cipher function f:
 *        a. Expansion (E): 32-bit R -> 48 bits
 *        b. Key mixing:    XOR expanded R with 48-bit subkey Kn
 *        c. Substitution:  8 S-boxes reduce 48 bits back to 32 bits
 *        d. Permutation (P): shuffle the 32-bit result
 *   4. Inverse Initial Permutation (IP^-1)
 */

// Helper function for gettting random numbers of len length
int secure_random(void *buffer, size_t len)
{
#if defined(_WIN32)
    return BCryptGenRandom(NULL, (PUCHAR)buffer, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    arc4random_buf(buffer, len);
    return 1;

#elif defined(__linux__)
    return getrandom(buffer, len, 0) == (ssize_t)len;

#else
#error "No secure random implementation available for this platform"
#endif
}

// Helper function for extracting bit n (1-based) from a 64-bit value
static inline int bit64(uint64_t v, int n)
{
    return (int)((v >> (64 - n)) & 1);
}

// Helper function for extracting bit n (1-based) from a 32-bit value
static inline int bit32(uint32_t v, int n)
{
    return (int)((v >> (32 - n)) & 1);
}

/* Initial Permutation (IP) - 64 entries */
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7};

/* Inverse Initial Permutation (IP^-1) - 64 entries */
static const int IP_INV[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25};

/* Expansion function (E): 32 bits -> 48 bits */
static const int E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1};

/* Post-S-box Permutation (P): 32 bits -> 32 bits */
static const int P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25};

/* Permuted Choice 1 (PC-1): selects C0 (bits 1-28) and D0 (bits 29-56)
 * from the 64-bit key. Parity bits (8, 16, 24, 32, 40, 48, 56, 64) are
 * intentionally skipped here, leaving 56 effective key bits. */
static const int PC1_C[28] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36};

static const int PC1_D[28] = {
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4};

/* Permuted Choice 2 (PC-2): 56-bit combined key -> 48-bit subkey */
static const int PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32};

/* Left-rotation amounts for each of the 16 rounds in the key schedule */
static const int KEY_SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1};

/* S-Boxes: 8 boxes, each with 4 rows x 16 columns.
 * Indexed as S[box][row * 16 + col].
 * Row is formed by bits 1 and 6 of the 6-bit input group;
 * column is formed by bits 2-5. */
static const int S[8][64] = {
    {/* S1 */
     14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {/* S2 */
     15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {/* S3 */
     10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {/* S4 */
     7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {/* S5 */
     2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {/* S6 */
     12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {/* S7 */
     4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {/* S8 */
     13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

// Helper function for key scheduling derive 16 x 48-bit subkeys from a 64-bit key
static void des_key_schedule(uint64_t key, uint64_t subkeys[16])
{
    printf("[Key Schedule] Deriving 16 x 48-bit subkeys via PC1 then PC-2\n");

    uint32_t C = 0, D = 0;

    for (int i = 0; i < 28; i++)
    {
        C = (C << 1) | (uint32_t)bit64(key, PC1_C[i]);
    }

    for (int i = 0; i < 28; i++)
    {
        D = (D << 1) | (uint32_t)bit64(key, PC1_D[i]);
    }

    printf("[Key Schedule] PC-1 applied: C0 = 0x%07X  D0 = 0x%07X\n", C, D);

    for (int round = 0; round < 16; round++)
    {
        int shift = KEY_SHIFTS[round];
        C = ((C << shift) | (C >> (28 - shift))) & 0x0FFFFFFF;
        D = ((D << shift) | (D >> (28 - shift))) & 0x0FFFFFFF;

        uint64_t CD = ((uint64_t)C << 28) | D;
        uint64_t Kn = 0;

        for (int i = 0; i < 48; i++)
        {
            int bit_pos = PC2[i];
            int bit_val = (int)((CD >> (56 - bit_pos)) & 1);
            Kn = (Kn << 1) | (uint64_t)bit_val;
        }

        subkeys[round] = Kn;
        printf("[Key Schedule] Round %2d: shift=%d  K%d = 0x%012llX\n", round + 1, shift, round + 1, (unsigned long long)Kn);
    }
}

// Helper function for the DES f function: takes 32-bit R and 48-bit subkey, returns 32-bit output
static uint32_t des_f(uint32_t R, uint64_t Kn, int round)
{
    uint64_t expanded = 0;
    for (int i = 0; i < 48; i++)
    {
        expanded = (expanded << 1) | (uint64_t)bit32(R, E[i]);
    }

    printf("  [Round %2d / f] E(R)        = 0x%012llX\n",
           round, (unsigned long long)expanded);

    uint64_t mixed = expanded ^ Kn;
    printf("  [Round %2d / f] E(R) XOR Kn = 0x%012llX\n",
           round, (unsigned long long)mixed);

    uint32_t sbox_out = 0;
    printf("  [Round %2d / f] S-box outputs:", round);

    for (int box = 0; box < 8; box++)
    {
        int shift = 42 - box * 6;
        int group = (int)((mixed >> shift) & 0x3F);
        int row = ((group & 0x20) >> 4) | (group & 0x01);
        int col = (group >> 1) & 0x0F;
        int val = S[box][row * 16 + col];

        sbox_out = (sbox_out << 4) | (uint32_t)val;
        printf(" S%d=%X", box + 1, val);
    }

    printf("\n");
    printf("  [Round %2d / f] S-box result = 0x%08X\n", round, sbox_out);

    uint32_t p_out = 0;
    for (int i = 0; i < 32; i++)
        p_out = (p_out << 1) | (uint32_t)bit32(sbox_out, P[i]);

    printf("  [Round %2d / f] P(S-box)     = 0x%08X\n", round, p_out);
    return p_out;
}

// Helper function for processing a single 64-bit block with the 16 subkeys
static uint64_t des_block(uint64_t block, uint64_t subkeys[16], int encrypt)
{
    printf("[DES Block] Applying Initial Permutation (IP)\n");
    uint64_t ip_out = 0;
    for (int i = 0; i < 64; i++)
    {
        ip_out = (ip_out << 1) | (uint64_t)bit64(block, IP[i]);
    }

    printf("[DES Block] IP result = 0x%016llX\n", (unsigned long long)ip_out);

    uint32_t L = (uint32_t)(ip_out >> 32);
    uint32_t R = (uint32_t)(ip_out & 0xFFFFFFFF);
    printf("[DES Block] Initial L = 0x%08X  R = 0x%08X\n", L, R);

    for (int round = 1; round <= 16; round++)
    {
        int ki = encrypt ? (round - 1) : (16 - round);
        printf("[DES Block] --- Round %2d (using K%d) ---\n", round, ki + 1);
        printf("  [Round %2d] L = 0x%08X  R = 0x%08X\n", round, L, R);

        uint32_t f_out = des_f(R, subkeys[ki], round);
        uint32_t new_R = L ^ f_out;
        uint32_t new_L = R;

        printf("  [Round %2d] new_L = 0x%08X  new_R = 0x%08X\n", round, new_L, new_R);
        L = new_L;
        R = new_R;
    }

    uint64_t pre_output = ((uint64_t)R << 32) | L;
    printf("[DES Block] Pre-output (R16||L16) = 0x%016llX\n",
           (unsigned long long)pre_output);

    printf("[DES Block] Applying Inverse Initial Permutation (IP^-1)\n");
    uint64_t output = 0;
    for (int i = 0; i < 64; i++)
        output = (output << 1) | (uint64_t)bit64(pre_output, IP_INV[i]);

    printf("[DES Block] IP^-1 result = 0x%016llX\n", (unsigned long long)output);
    return output;
}

int des_encrypt(const char *text, uint8_t *out, size_t out_size)
{
    printf("[Encrypt] Generating random DES key via system PRNG...\n");
    unsigned char key[8];
    if (!secure_random(key, sizeof(key)))
    {
        fprintf(stderr, "[Encrypt] ERROR: failed to generate random key\n");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < 8; i++)
    {
        unsigned char byte = key[i] & 0xFE;
        int ones = __builtin_popcount(byte);
        key[i] = byte | ((ones % 2 == 0) ? 1 : 0);
    }

    printf("[Encrypt] Key (hex):");
    for (int i = 0; i < 8; i++)
    {
        printf(" %02X", key[i]);
    }
    printf("\n");

    uint64_t key64 = 0;
    for (int i = 0; i < 8; i++)
    {
        key64 = (key64 << 8) | key[i];
    }

    uint64_t subkeys[16];
    des_key_schedule(key64, subkeys);

    size_t text_len = strlen(text);
    size_t blocks = (text_len + 7) / 8;
    size_t padded_len = blocks * 8;

    if (out_size < padded_len + 1)
    {
        fprintf(stderr, "[Encrypt] ERROR: output buffer too small\n");
        return EXIT_FAILURE;
    }

    printf("[Encrypt] Encrypting %zu byte(s) in %zu block(s)\n", text_len, blocks);

    for (size_t b = 0; b < blocks; b++)
    {
        uint64_t block = 0;
        for (int i = 0; i < 8; i++)
        {
            size_t idx = b * 8 + i;
            uint8_t byte = (idx < text_len) ? (uint8_t)text[idx] : 0x00;
            block = (block << 8) | byte;
        }

        printf("[Encrypt] Block %zu plaintext  = 0x%016llX\n", b, (unsigned long long)block);

        uint64_t cipher_block = des_block(block, subkeys, 1 /* encrypt */);

        for (int i = 7; i >= 0; i--)
        {
            out[b * 8 + i] = (uint8_t)(cipher_block & 0xFF);
            cipher_block >>= 8;
        }
    }

    return EXIT_SUCCESS;
}

int des_decrypt(const uint8_t *ciphertext, size_t cipher_len, uint64_t key64, char *out, size_t out_size)
{
    if (cipher_len % 8 != 0)
    {
        fprintf(stderr, "[Decrypt] ERROR: Ciphertext length (%zu) must be a multiple of 8\n", cipher_len);
        return EXIT_FAILURE;
    }

    size_t blocks = cipher_len / 8;

    if (out_size < (blocks * 8) + 1)
    {
        fprintf(stderr, "[Decrypt] ERROR: Output buffer too small\n");
        return EXIT_FAILURE;
    }

    printf("[Decrypt] Re-deriving subkeys from provided key...\n");
    uint64_t subkeys[16];
    des_key_schedule(key64, subkeys);

    printf("[Decrypt] Decrypting %zu block(s)\n", blocks);

    for (size_t b = 0; b < blocks; b++)
    {
        uint64_t block = 0;

        for (int i = 0; i < 8; i++)
        {
            block = (block << 8) | ciphertext[b * 8 + i];
        }

        printf("[Decrypt] Block %zu ciphertext = 0x%016llX\n", b, (unsigned long long)block);

        uint64_t plain_block = des_block(block, subkeys, 0 /* decrypt */);

        for (int i = 7; i >= 0; i--)
        {
            out[b * 8 + i] = (char)(plain_block & 0xFF);
            plain_block >>= 8;
        }
    }

    out[blocks * 8] = '\0';

    return EXIT_SUCCESS;
}