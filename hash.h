#ifndef HASH_H
#define HASH_H

#include "config.h"
#include <stddef.h>

typedef void (*HashFn)(const unsigned char *, size_t, unsigned char *);

typedef struct
{
    const char *name;
    size_t      digest_len;
    HashFn      fn;
} HashDef;

void hash_compute(HashAlgo algo, const char *input, size_t len, char *out_hex);

size_t hash_compute_raw(HashAlgo algo, const char *input, size_t len,
                        unsigned char *out_raw);

size_t hex_to_bytes(const char *hex, unsigned char *out);

extern const HashDef hash_table[];
extern const size_t  hash_table_size;

#endif