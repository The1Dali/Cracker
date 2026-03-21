#ifndef OUTPUT_H
#define OUTPUT_H

#include "config.h"
#include "hashfile.h"

/* Print a cracked hash to stdout and optionally to a file */
void output_print_crack(const Config *cfg, const Target *t);

/* Print a final summary */
void output_summary(int n_cracked, size_t n_total);

#endif