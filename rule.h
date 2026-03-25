#ifndef RULE_H
#define RULE_H

#include <stddef.h>


typedef size_t (*RuleFn)(const char *in, char *out, size_t out_size);


typedef struct
{
    const char *name;
    RuleFn      fn;
} RuleDef;


extern const RuleDef rule_table[];
extern const size_t  rule_count;

#endif