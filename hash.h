#ifndef HASH_H
#define HASH_H

#include "config.h"
#include <stddef.h>   


void hash_compute(HashAlgo algo, const char *input, size_t len, char *out_hex);

#endif