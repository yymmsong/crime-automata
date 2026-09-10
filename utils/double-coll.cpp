/*
The purpose of this script is to find all double-colliding sets for
some hash function and alphabet provided. More specifically, we want to find
all strings S, S' of length 5, where (using python-style string notation)
hash(S[:-1]) = hash(S[1:]) = hash(S'[:-1]) = hash(S'[1:]).

This script is intended for hash functions on 4-byte strings. For hash
functions on 3-byte strings (e.g. zlib/Gzip), you can find all such strings
pretty quickly even with a simple Python script. For hash functions on 5-byte
or longer strings (if there are any), you probably want to use a better script
that supports parallelism.

Five hash functions are supported:
- HASH_NG (zlib-ng >= 2.2.0, levels 1-8)
- HASH_NG_OLD (zlib-ng < 2.2.0, levels 1-8)
- HASH_CF (zlib-cloudflare)
- HASH_CR (zlib-chromium)
- HASH_GO (zlib-go, levels 2-9)
You can indicate the hash function you wish to use at compile time by defining
its corresponding macro to the compiler (preprocessor); for example, you can
provide the flag `-DHASH_CF` to `g++` to use the zlib-cloudflare hash function.
If no flag is provided, the hash function in zlib_go will be used by default.

Four alphabets are supported: ALPHANUM, PRINTABLE, ASCII, ALL_BYTES.
Again, you can indicate the alphabet by defining its macro before compilation.
The default alphabet is ALPHANUM.

You can also define these two macros for more refined output:
- ONLY_PRINT_FIRST_DIFF
    Only print double-colliding sets in which not all strings have the same
    first byte; note that the printed sets may still not be diverse.
- PRINT_THRESHOLD=n
    Omit from output double-colliding sets that are strictly smaller than n.

To use crc32c (used in HASH_NG_OLD and HASH_CF), Intel SSE4.2 support is
required. One possible way to compile:
g++ -Wall -msse4.2 -O3 double-coll.cpp -o double-coll
*/

#include <cstdio>
#include <cstring>
#include <vector>

typedef unsigned long long ull;

// #define HASH_GO  // mult. magic, big-endian, 17b
// #define HASH_NG  // mult. golden ratio, 16b
// #define HASH_NG_OLD // CRC32C, 16b
// #define HASH_CF // CRC32C, 15b
// #define HASH_CR  // mult. add. magic, little-endian, 15b

// #define ALPHANUM  // 0x30-0x39, 0x41-0x5a
// #define PRINTABLE // 0x20-0x7e
// #define ASCII // 0x00-0x7f
// #define ALL_BYTES  // 0x00-0xff

// #define ONLY_PRINT_FIRST_DIFF
#ifndef PRINT_THRESHOLD
#define PRINT_THRESHOLD 1
#endif

const int BYTE_MASK = 255;

#ifdef HASH_NG
const char* HASH_NAME = "HASH_NG";
const int HASH_BITS = 16;

inline unsigned int hash(unsigned int val) {
    return (val * 2654435761U) >> (32 - HASH_BITS);
}
#elif defined HASH_NG_OLD
const char* HASH_NAME = "HASH_NG_OLD";
const int HASH_BITS = 16;
#include <immintrin.h>

inline unsigned int hash(unsigned int val) {
    return _mm_crc32_u32(0, val) & ((1 << HASH_BITS) - 1);
}
#elif defined HASH_CF
const char* HASH_NAME = "HASH_CF";
const int HASH_BITS = 15;
#include <immintrin.h>

inline unsigned int hash(unsigned int val) {
    return _mm_crc32_u32(0, val) & ((1 << HASH_BITS) - 1);
}
#elif defined HASH_CR
const char* HASH_NAME = "HASH_CR";
const int HASH_BITS = 15;

inline unsigned int hash(unsigned int val) {
    return ((val * 66521 + 66521) >> 16) & ((1 << HASH_BITS) - 1);
}
#else  // if defined HASH_GO
const char* HASH_NAME = "HASH_GO";
const int HASH_BITS = 17;

inline unsigned int hash(unsigned int val) {
    // first switch val to big endian
    unsigned int val_big = ((val & BYTE_MASK) << 24) + (((val >> 8) & BYTE_MASK) << 16) + (((val >> 16) & BYTE_MASK) << 8) + (val >> 24);
    return (val_big * 506832829) >> (32 - HASH_BITS);
}
#endif

const int HASH_SIZE = (1 << HASH_BITS);

inline int is_alphanum(unsigned int c) {
    c &= BYTE_MASK;
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

inline int is_printable(unsigned int c) {
    c &= BYTE_MASK;
    return c >= ' ' && c <= '~';
}

inline int is_ascii(unsigned int c) {
    return !(c >> 7);
}

inline int is_byte(unsigned int c) {
    return 1;
}

#ifdef ALL_BYTES
const char* ALPHABET_NAME = "all";
int (*const is_cond)(unsigned int) = is_byte;
#elif defined ASCII
const char* ALPHABET_NAME = "ascii";
int (*const is_cond)(unsigned int) = is_ascii;
#elif defined PRINTABLE
const char* ALPHABET_NAME = "printable";
int (*const is_cond)(unsigned int) = is_printable;
#else  // if defined ALPHANUM
const char* ALPHABET_NAME = "alphanumeric";
int (*const is_cond)(unsigned int) = is_alphanum;
#endif

int first_diff[HASH_SIZE];

using std::vector;

int main() {
    ull cnt = 0;
    vector<vector<ull> > colls(HASH_SIZE);

    memset(first_diff, 0, sizeof(first_diff));

    for (unsigned int a = 0; a < 256; a++) {
        if (!is_cond(a)) continue;
        for (unsigned int b = 0; b < 256; b++) {
            if (!is_cond(b)) continue;
            for (unsigned int c = 0; c < 256; c++) {
                if (!is_cond(c)) continue;
                for (unsigned int d = 0; d < 256; d++) {
                    if (!is_cond(d)) continue;
                    unsigned int x = a + (b << 8) + (c << 16) + (d << 24);
                    unsigned int h = hash(x);
                    for (unsigned int e = 0; e < 256; e++) {
                        if (!is_cond(e)) continue;
                        unsigned int y = (x >> 8) + (e << 24);
                        if (h == hash(y)) {
                            ++cnt;
                            vector<ull>& cur_colls = colls[h];
                            if (!cur_colls.empty()) first_diff[h] |= (a != (cur_colls[0] & BYTE_MASK));
                            cur_colls.push_back((((ull)e) << 32) + x);
                        }
                    }
                }
            }
        }
    }

    printf("total number of double collisions for %s on %s bytes: %lld\n", HASH_NAME, ALPHABET_NAME, cnt);

    for (int h = 0; h < HASH_SIZE; h++) {
#ifdef ONLY_PRINT_FIRST_DIFF
        if (!first_diff[h])
            continue;
#endif

        int sz = colls[h].size();
        if (sz < PRINT_THRESHOLD) continue;
        printf("Hash value: %d,\tfirst_diff: %d,\tcount: %d,\tcandidates:\t", h, first_diff[h], sz);
        for (int i = 0; i < sz; i++) {
            ull x = colls[h][i];
#if defined(ASCII) || defined(ALL_BYTES)
            printf("%#010llx\t", x);
#elif defined(ALPHANUM) || defined(PRINTABLE)
            printf("%#010llx \"%s\"\t", x, (char*)&x);
#endif
        }
        printf("\n");
    }
    return 0;
}
