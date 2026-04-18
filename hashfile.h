#ifndef HASHFILE_H
#define HASHFILE_H

#include <stddef.h>
typedef struct
{
    char          hash_hex[129];
    unsigned char digest[64];
    size_t        digest_len;
    char          salt[64];
    size_t        salt_len;
    int           has_salt;
    char          username[256];
    char          plaintext[256];
    int           cracked;
} Target;

int hashfile_load(const char *path, Target **targets, size_t *count,
                  size_t *n_unsalted);

#endif