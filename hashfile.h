#ifndef HASHFILE_H
#define HASHFILE_H

#include <stddef.h>


typedef struct
{
    char          hash_hex[129];
    unsigned char digest[64];
    size_t        digest_len;
    char          username[256];
    char          plaintext[256];
    int           cracked;
} Target;


int hashfile_load(const char *path, Target **targets, size_t *count);

#endif