#ifndef _BS_H_
#define _BS_H_

#include <stdint.h>

#define BLOCK_SIZE          128
#define KEY_SCHEDULE_SIZE   176
#define WORD_SIZE           64
#define BS_BLOCK_SIZE       (BLOCK_SIZE * WORD_SIZE / 8)
#define WORDS_PER_BLOCK     (BLOCK_SIZE / WORD_SIZE)

#if (WORD_SIZE==64)
    typedef uint64_t    word_t;
    #define ONE         1ULL
    #define MUL_SHIFT   6
    #define WFMT        "lx"
    #define WPAD        "016"
    #define __builtin_bswap_wordsize(x) __builtin_bswap64(x)
#elif (WORD_SIZE==32)
    typedef uint32_t    word_t;
    #define ONE         1UL
    #define MUL_SHIFT   5
    #define WFMT        "x"
    #define WPAD        "08"
    #define __builtin_bswap_wordsize(x) __builtin_bswap32(x)
#elif (WORD_SIZE==16)
    typedef uint16_t    word_t;
    #define ONE         1
    #define MUL_SHIFT   4
    #define WFMT        "hx"
    #define WPAD        "04"
    #define __builtin_bswap_wordsize(x) __builtin_bswap16(x)
#elif (WORD_SIZE==8)
    typedef uint8_t     word_t;
    #define ONE         1
    #define MUL_SHIFT   3
    #define WFMT        "hhx"
    #define WPAD        "02"
    #define __builtin_bswap_wordsize(x) (x)
#else
#error "invalid word size"
#endif

void bs_transpose(word_t * blocks);
void bs_transpose_rev(word_t * blocks);
void bs_transpose_dst(word_t * transpose, word_t * blocks);

void bs_sbox(word_t U[8]);
void bs_sbox_rev(word_t U[8]);

void bs_shiftrows(word_t * B);
void bs_shiftrows_rev(word_t * B);

void bs_mixcolumns(word_t * B);
void bs_mixcolumns_rev(word_t * B);

void bs_shiftmix(word_t * B);

void bs_addroundkey(word_t * B, word_t * rk);
void bs_apply_sbox(word_t * input);
void bs_apply_sbox_rev(word_t * input);


void expand_key(unsigned char *in);
void bs_expand_key(word_t (* rk)[BLOCK_SIZE], uint8_t * key);

void bs_cipher(word_t state[BLOCK_SIZE], word_t (* rk)[BLOCK_SIZE]);
void bs_cipher_rev(word_t state[BLOCK_SIZE], word_t (* rk)[BLOCK_SIZE]);

#endif
