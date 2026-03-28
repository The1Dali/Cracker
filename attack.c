#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
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

        if (cmp == 0)       return &targets[mid];
        else if (cmp < 0)
        {
            if (mid == 0) break;
            hi = mid - 1;
        }
        else                lo = mid + 1;
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

static size_t next_word(const char **pos, const char *end,
                        char *out, size_t out_size)
{
    if (*pos >= end) return 0;

    const char *start  = *pos;
    const char *cursor = start;

    while (cursor < end && *cursor != '\n')
    {
        cursor++;
    }

    const char *line_end = cursor;

    *pos = (cursor < end) ? cursor + 1 : end;

    if (line_end > start && *(line_end - 1) == '\r')
    {
        line_end--;
    }

    size_t word_len = (size_t)(line_end - start);

    if (word_len == 0) return 0;

    if (word_len + 1 > out_size) return 0;

    memcpy(out, start, word_len);
    out[word_len] = '\0';

    return word_len;
}

int run_dictionary(const Config *cfg, Target *targets, size_t n_targets)
{
    int fd = open(cfg->wordlist, O_RDONLY);
    if (fd == -1)
    {
        perror("run_dictionary: open wordlist");
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) == -1)
    {
        perror("run_dictionary: fstat");
        close(fd);
        return 0;
    }

    size_t file_size = (size_t)st.st_size;

    if (file_size == 0)
    {
        close(fd);
        return 0;
    }

    const char *map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED)
    {
        perror("run_dictionary: mmap");
        close(fd);
        return 0;
    }

    close(fd);

    const char *pos = map;           
    const char *end = map + file_size;   

    char     word[256];
    char     variant[256];
    uint64_t count     = 0;
    int      n_cracked = 0;

    while (1)
    {
        size_t word_len = next_word(&pos, end, word, sizeof(word));

        if (word_len == 0)
        {
            if (pos >= end) break;
            continue;
        }

        for (size_t r = 0; r < rule_count; r++)
        {
            size_t vlen = rule_table[r].fn(word, variant, sizeof(variant));
            if (vlen == 0) continue;

            try_candidate(cfg, targets, n_targets, variant, &n_cracked);

            if ((size_t)n_cracked == n_targets)
            {
                munmap((void *)map, file_size);
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

    munmap((void *)map, file_size);
    return n_cracked;
}

int run_bruteforce(const Config *cfg, Target *targets, size_t n_targets)
{
    const char *charset     = cfg->charset;
    size_t      charset_len = strlen(charset);

    if (charset_len == 0)
    {
        fprintf(stderr, "Error: charset is empty\n");
        return 0;
    }

    int min_len = cfg->min_len;
    int max_len = cfg->max_len;

    if (min_len < 1)        min_len = 1;
    if (max_len < min_len)  max_len = min_len;
    if (max_len > MAX_BF_LEN)
    {
        fprintf(stderr, "Warning: max_len capped at %d\n", MAX_BF_LEN);
        max_len = MAX_BF_LEN;
    }

    uint64_t count     = 0;
    int      n_cracked = 0;

    for (int len = min_len; len <= max_len; len++)
    {
        if (cfg->verbose)
        {
            fprintf(stderr, "[*] Brute forcing length %d...\n", len);
        }

        size_t indices[MAX_BF_LEN];
        memset(indices, 0, sizeof(indices));

        char candidate[MAX_BF_LEN + 1];
        candidate[len] = '\0';

        while (1)
        {
            for (int i = 0; i < len; i++)
            {
                candidate[i] = charset[indices[i]];
            }

            try_candidate(cfg, targets, n_targets, candidate, &n_cracked);

            if ((size_t)n_cracked == n_targets) return n_cracked;

            count++;

            if (cfg->verbose && count % 500000 == 0)
            {
                fprintf(stderr, "\r[*] Tried: %"PRIu64" candidates | Cracked: %d/%zu",
                        count, n_cracked, n_targets);
                fflush(stderr);
            }

            int pos = len - 1;
            while (pos >= 0)
            {
                indices[pos]++;
                if (indices[pos] < charset_len) break;
                indices[pos] = 0;
                pos--;
            }
            if (pos < 0) break;
        }
    }

    if (cfg->verbose) fprintf(stderr, "\n");
    return n_cracked;
}

int run_auto(const Config *cfg, Target *targets, size_t n_targets)
{
    int total_cracked = 0;

    if (cfg->wordlist[0] != '\0')
    {
        fprintf(stderr, "[*] Auto mode — phase 1: dictionary attack...\n");
        int cracked = run_dictionary(cfg, targets, n_targets);
        total_cracked += cracked;
        fprintf(stderr, "[*] Phase 1 complete: %d/%zu cracked\n",
                total_cracked, n_targets);

        if ((size_t)total_cracked == n_targets) return total_cracked;
    }
    else
    {
        fprintf(stderr, "[*] Auto mode — skipping phase 1 (no wordlist provided)\n");
    }

    if (cfg->charset[0] != '\0')
    {
        fprintf(stderr, "[*] Auto mode — phase 2: brute force on %zu remaining target(s)...\n",
                n_targets - (size_t)total_cracked);
        int cracked = run_bruteforce(cfg, targets, n_targets);
        total_cracked += cracked;
        fprintf(stderr, "[*] Phase 2 complete: %d/%zu cracked\n",
                total_cracked, n_targets);
    }
    else
    {
        fprintf(stderr, "[*] Auto mode — skipping phase 2 (no charset provided, use -c)\n");
    }

    return total_cracked;
}