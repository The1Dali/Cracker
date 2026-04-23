#ifndef ATTACK_H
#define ATTACK_H

#include <signal.h>
#include "config.h"
#include "hashfile.h"

extern volatile sig_atomic_t g_interrupted;

int run_dictionary(const Config *cfg, Target *targets, size_t n_targets,
                   size_t n_unsalted);

int run_bruteforce(const Config *cfg, Target *targets, size_t n_targets,
                   size_t n_unsalted);

int run_auto(const Config *cfg, Target *targets, size_t n_targets,
             size_t n_unsalted);

void run_benchmark(int duration_secs);

int run_mask(const Config *cfg, Target *targets, size_t n_targets,
             size_t n_unsalted);

int run_autodetect(Config *cfg, Target *targets, size_t n_targets,
                   size_t n_unsalted);

int run_rainbow(const Config *cfg, Target *targets, size_t n_targets);

#endif