#include <stdio.h>   
#include <stdlib.h>  
#include <string.h>   
#include "config.h"
#include "hashfile.h"
#include "hash.h"
#include "attack.h"

static void print_usage(const char *prog_name) 
{
    fprintf(stderr, "Usage: %s -m <hash_type> -w <wordlist> <hashfile>\n"
        "\nHash types:\n"
        "  0 = MD5\n"
        "  1 = SHA-256\n"
        "  2 = SHA-512\n"
        "  3 = NTLM\n"
        "\nExample:\n"
        "  %s -m 0 -w rockyou.txt hashes.txt\n", prog_name, prog_name);
}

int main(int argc, char *argv[]) 
{
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));    
    cfg.algo    = HASH_MD5;         
    cfg.verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -m requires a value\n");
                return 1;
            }
            cfg.algo = (HashAlgo)atoi(argv[++i]);

        } else if (strcmp(argv[i], "-w") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -w requires a value\n");
                return 1;
            }
            strncpy(cfg.wordlist, argv[++i], sizeof(cfg.wordlist) - 1);

        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: -o requires a value\n");
                return 1;
            }
            strncpy(cfg.outfile, argv[++i], sizeof(cfg.outfile) - 1);

        } else if (strcmp(argv[i], "-v") == 0) {
            cfg.verbose = 1;

        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;

        } else {
            strncpy(cfg.hashfile, argv[i], sizeof(cfg.hashfile) - 1);
        }
    }

    if (cfg.hashfile[0] == '\0') {
        fprintf(stderr, "Error: no hash file specified\n");
        print_usage(argv[0]);
        return 1;
    }
    if (cfg.wordlist[0] == '\0') {
        fprintf(stderr, "Error: no wordlist specified (-w)\n");
        print_usage(argv[0]);
        return 1;
    }

    Target  *targets   = NULL;
    size_t   n_targets = 0;

    if (hashfile_load(cfg.hashfile, &targets, &n_targets) != 0) {
        fprintf(stderr, "Error: could not load hash file\n");
        return 1;
    }

    fprintf(stderr, "[*] Loaded %zu target hash(es)\n", n_targets);
    fprintf(stderr, "[*] Starting dictionary attack...\n");

    int cracked = run_dictionary(&cfg, targets, n_targets);

    fprintf(stderr, "[*] Done. %d/%zu cracked.\n", cracked, n_targets);

    free(targets);
    return 0;
}