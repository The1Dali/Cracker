#include <stdio.h>
#include <string.h>
#include "output.h"

void output_print_crack(const Config *cfg, const Target *t) {
    if (t->username[0] != '\0') {
        printf("%s:%s:%s\n", t->username, t->hash_hex, t->plaintext);
    } else {
        printf("%s:%s\n", t->hash_hex, t->plaintext);
    }
    fflush(stdout);   

    if (cfg->outfile[0] != '\0') {
        FILE *fp = fopen(cfg->outfile, "a");   
        if (fp) {
            if (t->username[0] != '\0') {
                fprintf(fp, "%s:%s:%s\n", t->username, t->hash_hex, t->plaintext);
            } else {
                fprintf(fp, "%s:%s\n", t->hash_hex, t->plaintext);
            }
            fclose(fp);
        }
    }
}

void output_summary(int n_cracked, size_t n_total) {
    fprintf(stderr, "\n[+] Session complete: %d/%zu cracked\n",
            n_cracked, n_total);
}