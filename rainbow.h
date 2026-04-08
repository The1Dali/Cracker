#ifndef RAINBOW_H
#define RAINBOW_H

#include <stddef.h>

typedef struct RainbowEntry
{
    const char         *key;
    size_t              key_len;
    const char         *value;
    size_t              val_len;
    struct RainbowEntry *next;
} RainbowEntry;

typedef struct
{
    RainbowEntry **buckets;
    size_t         n_buckets;
    RainbowEntry  *entries;
    size_t         n_entries;
    const char    *map;
    size_t         map_size;
} RainbowMap;

int rainbow_load(const char *path, RainbowMap *out);

const char *rainbow_lookup(const RainbowMap *map, const char *hex, size_t *val_len_out);
                            
void rainbow_free(RainbowMap *map);

#endif