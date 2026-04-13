#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "session.h"

int session_save(const char *path, size_t wordlist_offset,
                 const Target *targets, size_t n_targets, int n_cracked)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
    {
        perror("session_save: fopen");
        return -1;
    }

    fprintf(fp, "offset %zu\n", wordlist_offset);
    fprintf(fp, "cracked %d\n", n_cracked);

    for (size_t i = 0; i < n_targets; i++)
    {
        if (targets[i].cracked)
        {
            fprintf(fp, "result %s %s\n",
                    targets[i].hash_hex,
                    targets[i].plaintext);
        }
    }

    fclose(fp);
    return 0;
}

int session_restore(const char *path, Session *out,
                    Target *targets, size_t n_targets)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        return -1;
    }

    out->wordlist_offset = 0;
    out->n_cracked       = 0;

    char line[1024];

    while (fgets(line, sizeof(line), fp))
    {
        line[strcspn(line, "\r\n")] = '\0';

        if (strncmp(line, "offset ", 7) == 0)
        {
            sscanf(line + 7, "%zu", &out->wordlist_offset);
        }
        else if (strncmp(line, "cracked ", 8) == 0)
        {
            sscanf(line + 8, "%d", &out->n_cracked);
        }
        else if (strncmp(line, "result ", 7) == 0)
        {
            char hash_hex[129];
            char plaintext[256];

            if (sscanf(line + 7, "%128s %255s", hash_hex, plaintext) != 2)
            {
                continue;   
            }

            for (size_t i = 0; i < n_targets; i++)
            {
                if (strcmp(targets[i].hash_hex, hash_hex) == 0)
                {
                    strncpy(targets[i].plaintext, plaintext, 255);
                    targets[i].cracked = 1;
                    break;
                }
            }
        }
    }

    fclose(fp);
    return 0;
}