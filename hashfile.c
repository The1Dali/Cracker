#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashfile.h"
#include "hash.h"


static int compare_targets(const void *a, const void *b)
{
    const Target *ta = (const Target *)a;
    const Target *tb = (const Target *)b;
    return memcmp(ta->digest, tb->digest, 64);
}


int hashfile_load(const char *path, Target **targets, size_t *count)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        perror("hashfile_load: fopen");
        return -1;
    }

    size_t n = 0;
    char   line[1024];

    while (fgets(line, sizeof(line), fp))
    {
        if (line[0] == '\n' || line[0] == '#') continue;
        n++;
    }

    if (n == 0)
    {
        fclose(fp);
        *targets = NULL;
        *count   = 0;
        return 0;
    }

    
    *targets = calloc(n, sizeof(Target));
    if (!*targets)
    {
        fclose(fp);
        return -1;
    }

    rewind(fp);
    size_t idx = 0;

    while (fgets(line, sizeof(line), fp) && idx < n)
    {
        if (line[0] == '\n' || line[0] == '#') continue;

        line[strcspn(line, "\r\n")] = '\0';

        char *colon = strchr(line, ':');
        if (colon)
        {
            *colon = '\0';
            strncpy((*targets)[idx].username, line,        255);
            strncpy((*targets)[idx].hash_hex, colon + 1,  128);
        }
        else
        {
            strncpy((*targets)[idx].hash_hex, line, 128);
        }

        (*targets)[idx].digest_len = hex_to_bytes(
            (*targets)[idx].hash_hex,
            (*targets)[idx].digest
        );

        idx++;
    }

    fclose(fp);
    *count = idx;

    qsort(*targets, *count, sizeof(Target), compare_targets);

    return 0;
}