#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "attack.h"
#include "hash.h"
#include "output.h"
#include "rule.h"

static Target *binary_search(Target *targets, size_t n_targets,
                              const unsigned char *digest, size_t digest_len)
{
    if (n_targets == 0) return NULL;

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

static int try_candidate(const Config *cfg, Target *targets, size_t n_targets,
                         const char *candidate, int *n_cracked)
{
    unsigned char digest[64];

    size_t digest_len = hash_compute_raw(cfg->algo, candidate, strlen(candidate),
                                         digest);
    if (digest_len == 0) return 0;

    Target *match = binary_search(targets, n_targets, digest, digest_len);

    if (match != NULL && !match->cracked)
    {
        strncpy(match->plaintext, candidate, 255);
        match->cracked = 1;
        (*n_cracked)++;

        output_print_crack(cfg, match);
        return 1;
    }

    return 0;
}

int run_dictionary(const Config *cfg, Target *targets, size_t n_targets)
{
    FILE *wl = fopen(cfg->wordlist, "r");
    if (!wl)
    {
        perror("run_dictionary: fopen wordlist");
        return 0;
    }

    char     word[256];
    char     variant[256];
    uint64_t count     = 0;
    int      n_cracked = 0;

    while (fgets(word, sizeof(word), wl))
    {
        word[strcspn(word, "\r\n")] = '\0';
        if (word[0] == '\0') continue;

        for (size_t r = 0; r < rule_count; r++)
        {
            size_t vlen = rule_table[r].fn(word, variant, sizeof(variant));
            if (vlen == 0) continue;

            try_candidate(cfg, targets, n_targets, variant, &n_cracked);

            if ((size_t)n_cracked == n_targets)
            {
                fclose(wl);
                return n_cracked;
            }
        }

        count++;

        if (cfg->verbose && count % 500000 == 0)
        {
            fprintf(stderr, "\r[*] Tried: %"PRIu64" words | Cracked: %d/%zu",
                    count, n_cracked, n_targets);
            fflush(stderr);
        }
    }

    if (cfg->verbose) fprintf(stderr, "\n");

    fclose(wl);
    return n_cracked;
}