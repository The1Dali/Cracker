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

#endif