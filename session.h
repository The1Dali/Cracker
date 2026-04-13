#ifndef SESSION_H
#define SESSION_H

#include <stddef.h>
#include "hashfile.h"

typedef struct
{
    size_t wordlist_offset;
    int    n_cracked;
} Session;

int session_save(const char *path, size_t wordlist_offset,
                 const Target *targets, size_t n_targets, int n_cracked);

int session_restore(const char *path, Session *out,
                    Target *targets, size_t n_targets);

#endif