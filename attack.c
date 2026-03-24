#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "attack.h"
#include "hash.h"
#include "output.h"


static Target *binary_search(Target *targets, size_t n_targets, const unsigned char *digest, size_t digest_len)
{
    if (n_targets == 0)
    {
        return NULL;
    }

    size_t lo = 0;
    size_t hi = n_targets - 1;

    while (lo <= hi)
    {
        size_t mid = lo + (hi - lo) / 2;
        int    cmp = memcmp(digest, targets[mid].digest, digest_len);

        if (cmp == 0)
        {
            return &targets[mid];
        }
        else if (cmp < 0)
        {
            if (mid == 0) break;
            hi = mid - 1;
        }
        else
        {
            lo = mid + 1;
        }
    }

    return NULL;
}


int run_dictionary(const Config *cfg, Target *targets, size_t n_targets)
{
    FILE *wl = fopen(cfg->wordlist, "r");
    if (!wl)
    {
        perror("run_dictionary: fopen wordlist");
        return 0;
    }

    char          word[256];
    unsigned char candidate_digest[64];
    uint64_t      count     = 0;
    int           n_cracked = 0;

    while (fgets(word, sizeof(word), wl))
    {
        word[strcspn(word, "\r\n")] = '\0';

        if (word[0] == '\0') continue;


        size_t digest_len = hash_compute_raw(cfg->algo, word, strlen(word), candidate_digest);

        if (digest_len == 0) continue;

        Target *match = binary_search(targets, n_targets,
                                      candidate_digest, digest_len);

        if (match != NULL && !match->cracked)
        {
            strncpy(match->plaintext, word, 255);
            match->cracked = 1;
            n_cracked++;

            output_print_crack(cfg, match);

            if ((size_t)n_cracked == n_targets)
            {
                fclose(wl);
                return n_cracked;
            }
        }

        count++;

        if (cfg->verbose && count % 500000 == 0)
        {
            fprintf(stderr, "\r[*] Tried: %"PRIu64" candidates | Cracked: %d/%zu",
                    count, n_cracked, n_targets);
            fflush(stderr);
        }
    }

    if (cfg->verbose) fprintf(stderr, "\n");

    fclose(wl);
    return n_cracked;
}