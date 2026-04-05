#ifndef ATTACK_H
#define ATTACK_H

#include "config.h"
#include "hashfile.h"

int run_dictionary(const Config *cfg, Target *targets, size_t n_targets);

int run_bruteforce(const Config *cfg, Target *targets, size_t n_targets);

int run_auto(const Config *cfg, Target *targets, size_t n_targets);

void run_benchmark(int duration_secs);

int run_mask(const Config *cfg, Target *targets, size_t n_targets);

int run_autodetect(Config *cfg, Target *targets, size_t n_targets);

#endif