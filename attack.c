#include <stdio.h>
#include <string.h>
#include <inttypes.h>  
#include "attack.h"
#include "hash.h"
#include "output.h"

int run_dictionary(const Config *cfg, Target *targets, size_t n_targets) {
    FILE *wl = fopen(cfg->wordlist, "r");
    if (!wl) {
        perror("run_dictionary: fopen wordlist");
        return 0;
    }

    char     word[256];         
    char     candidate_hash[129];
    uint64_t count    = 0;     
    int      n_cracked = 0;    

    while (fgets(word, sizeof(word), wl)) {
        word[strcspn(word, "\r\n")] = '\0';

        if (word[0] == '\0') continue;

        hash_compute(cfg->algo, word, strlen(word), candidate_hash);

        for (size_t i = 0; i < n_targets; i++) {
            if (targets[i].cracked) continue;  

            if (strcmp(candidate_hash, targets[i].hash_hex) == 0) {
                strncpy(targets[i].plaintext, word, 255);
                targets[i].cracked = 1;
                n_cracked++;

                output_print_crack(cfg, &targets[i]);

                if ((size_t)n_cracked == n_targets) {
                    fclose(wl);
                    return n_cracked;
                }
            }
        }

        count++;

        if (cfg->verbose && count % 500000 == 0) {
            fprintf(stderr, "\r[*] Tried: %"PRIu64" candidates | Cracked: %d/%zu",
                    count, n_cracked, n_targets);
            fflush(stderr);
        }
    }

    if (cfg->verbose) fprintf(stderr, "\n");

    fclose(wl);
    return n_cracked;
}