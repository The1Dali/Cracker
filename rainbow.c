#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "rainbow.h"

#define N_BUCKETS 1048573

static size_t map_hash(const char *key, size_t key_len, size_t n_buckets)
{
    unsigned long long hash = 14695981039346656037ULL;  

    for (size_t i = 0; i < key_len; i++)
    {
        hash ^= (unsigned char)key[i];
        hash *= 1099511628211ULL;                     
    }

    return (size_t)(hash % (unsigned long long)n_buckets);
}

static size_t count_lines(const char *map, size_t size)
{
    size_t count = 0;
    const char *pos = map;
    const char *end = map + size;

    while (pos < end)
    {
        const char *line_start = pos;

        while (pos < end && *pos != '\n') pos++;
        if (pos < end) pos++;  

        if (line_start == pos - 1) continue;   
        if (*line_start == '#')    continue;   

        count++;
    }

    return count;
}

int rainbow_load(const char *path, RainbowMap *out)
{
    int fd = open(path, O_RDONLY);
    if (fd == -1)
    {
        perror("rainbow_load: open");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        perror("rainbow_load: fstat");
        close(fd);
        return -1;
    }

    size_t file_size = (size_t)st.st_size;
    if (file_size == 0)
    {
        close(fd);
        out->map      = NULL;
        out->map_size = 0;
        out->buckets  = NULL;
        out->entries  = NULL;
        out->n_entries = 0;
        return 0;
    }

    const char *map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        perror("rainbow_load: mmap");
        close(fd);
        return -1;
    }

    close(fd);

    size_t n_lines = count_lines(map, file_size);

    out->buckets = calloc(N_BUCKETS, sizeof(RainbowEntry *));
    if (!out->buckets)
    {
        munmap((void *)map, file_size);
        return -1;
    }

    out->entries = calloc(n_lines, sizeof(RainbowEntry));
    if (!out->entries)
    {
        free(out->buckets);
        munmap((void *)map, file_size);
        return -1;
    }

    out->n_buckets  = N_BUCKETS;
    out->n_entries  = 0;
    out->map        = map;
    out->map_size   = file_size;

    const char *pos = map;
    const char *end = map + file_size;

    while (pos < end)
    {
        const char *line_start = pos;

        while (pos < end && *pos != '\n') pos++;
        const char *line_end = pos;
        if (pos < end) pos++;   

        if (line_end > line_start && *(line_end - 1) == '\r') line_end--;

        size_t line_len = (size_t)(line_end - line_start);
        if (line_len == 0)           continue;
        if (*line_start == '#')      continue;

        const char *colon = NULL;
        for (const char *p = line_start; p < line_end; p++)
        {
            if (*p == ':') { colon = p; break; }
        }

        if (colon == NULL || colon == line_start || colon + 1 >= line_end)
        {
            continue;
        }

        RainbowEntry *entry = &out->entries[out->n_entries++];
        entry->key     = line_start;
        entry->key_len = (size_t)(colon - line_start);
        entry->value   = colon + 1;
        entry->val_len = (size_t)(line_end - (colon + 1));

        size_t slot  = map_hash(entry->key, entry->key_len, N_BUCKETS);
        entry->next  = out->buckets[slot];   
        out->buckets[slot] = entry;         
    }

    return 0;
}

const char *rainbow_lookup(const RainbowMap *map, const char *hex,
                            size_t *val_len_out)
{
    if (map->buckets == NULL) return NULL;

    size_t key_len = strlen(hex);
    size_t slot    = map_hash(hex, key_len, map->n_buckets);

    for (RainbowEntry *e = map->buckets[slot]; e != NULL; e = e->next)
    {
        if (e->key_len == key_len &&
            strncmp(e->key, hex, key_len) == 0)
        {
            *val_len_out = e->val_len;
            return e->value;
        }
    }

    return NULL;
}

void rainbow_free(RainbowMap *map)
{
    free(map->buckets);
    free(map->entries);

    if (map->map != NULL)
    {
        munmap((void *)map->map, map->map_size);
    }

    map->buckets   = NULL;
    map->entries   = NULL;
    map->map       = NULL;
    map->n_entries = 0;
}