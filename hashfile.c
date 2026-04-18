#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashfile.h"
#include "hash.h"

static int compare_targets(const void *a, const void *b)
{
    const Target *ta = (const Target *)a;
    const Target *tb = (const Target *)b;

    if (ta->has_salt != tb->has_salt)
    {
        return ta->has_salt - tb->has_salt;
    }

    if (!ta->has_salt)
    {
        return memcmp(ta->digest, tb->digest, 64);
    }

    return 0;
}

int hashfile_load(const char *path, Target **targets, size_t *count,
                  size_t *n_unsalted)
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
        *targets    = NULL;
        *count      = 0;
        *n_unsalted = 0;
        return 0;
    }

    *targets = calloc(n, sizeof(Target));
    if (!*targets)
    {
        fclose(fp);
        return -1;
    }

    rewind(fp);
    size_t idx           = 0;
    size_t local_unsalted = 0;

    while (fgets(line, sizeof(line), fp) && idx < n)
    {
        if (line[0] == '\n' || line[0] == '#') continue;

        line[strcspn(line, "\r\n")] = '\0';

        char *colon = strchr(line, ':');
        char *hash_field;

        if (colon)
        {
            *colon = '\0';
            strncpy((*targets)[idx].username, line, 255);
            hash_field = colon + 1;
        }
        else
        {
            hash_field = line;
        }

        char *dollar = strchr(hash_field, '$');

        if (dollar)
        {
            *dollar = '\0';                    
            strncpy((*targets)[idx].hash_hex, hash_field, 128);

            char *salt_str = dollar + 1;
            size_t slen    = strlen(salt_str);
            if (slen > 63) slen = 63;         
            memcpy((*targets)[idx].salt, salt_str, slen);
            (*targets)[idx].salt[slen] = '\0';
            (*targets)[idx].salt_len   = slen;
            (*targets)[idx].has_salt   = 1;
        }
        else
        {
            strncpy((*targets)[idx].hash_hex, hash_field, 128);
            (*targets)[idx].has_salt = 0;
            (*targets)[idx].salt_len = 0;
            local_unsalted++;
        }

        (*targets)[idx].digest_len = hex_to_bytes(
            (*targets)[idx].hash_hex,
            (*targets)[idx].digest
        );

        idx++;
    }

    fclose(fp);
    *count      = idx;
    *n_unsalted = local_unsalted;

    qsort(*targets, *count, sizeof(Target), compare_targets);

    return 0;
}