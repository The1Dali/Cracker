#ifndef OUTPUT_H
#define OUTPUT_H

#include "config.h"
#include "hashfile.h"

void output_print_crack(const Config *cfg, const Target *t);

void output_summary(int n_cracked, size_t n_total);

#endif