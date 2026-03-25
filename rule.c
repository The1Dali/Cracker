#include <string.h>
#include <ctype.h>
#include "rule.h"


static size_t rule_identity(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 1 > out_size) return 0;
    memcpy(out, in, len + 1);
    return len;
}

static size_t rule_capitalize(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 1 > out_size) return 0;

    for (size_t i = 0; i < len; i++)
    {
        if (i == 0)
        {
            out[i] = (char)toupper((unsigned char)in[i]);
        }
        else
        {
            out[i] = (char)tolower((unsigned char)in[i]);
        }
    }
    out[len] = '\0';
    return len;
}

static size_t rule_uppercase(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 1 > out_size) return 0;

    for (size_t i = 0; i < len; i++)
    {
        out[i] = (char)toupper((unsigned char)in[i]);
    }
    out[len] = '\0';
    return len;
}

static size_t rule_reverse(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 1 > out_size) return 0;

    for (size_t i = 0; i < len; i++)
    {
        out[i] = in[len - 1 - i];
    }
    out[len] = '\0';
    return len;
}

static size_t rule_leet(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 1 > out_size) return 0;

    for (size_t i = 0; i < len; i++)
    {
        char c = (char)tolower((unsigned char)in[i]);
        switch (c)
        {
            case 'a': out[i] = '4'; break;
            case 'e': out[i] = '3'; break;
            case 'i': out[i] = '1'; break;
            case 'o': out[i] = '0'; break;
            case 's': out[i] = '5'; break;
            default:  out[i] = in[i]; break;
        }
    }
    out[len] = '\0';
    return len;
}

static size_t rule_append_1(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 2 > out_size) return 0;

    memcpy(out, in, len);
    out[len]     = '1';
    out[len + 1] = '\0';
    return len + 1;
}

static size_t rule_append_bang(const char *in, char *out, size_t out_size)
{
    size_t len = strlen(in);
    if (len + 2 > out_size) return 0;

    memcpy(out, in, len);
    out[len]     = '!';
    out[len + 1] = '\0';
    return len + 1;
}

static size_t rule_append_123(const char *in, char *out, size_t out_size)
{
    size_t len        = strlen(in);
    size_t suffix_len = 3;
    if (len + suffix_len + 1 > out_size) return 0;

    memcpy(out, in, len);
    memcpy(out + len, "123", suffix_len);
    out[len + suffix_len] = '\0';
    return len + suffix_len;
}

const RuleDef rule_table[] =
{
    { "identity",     rule_identity    },
    { "capitalize",   rule_capitalize  },
    { "uppercase",    rule_uppercase   },
    { "reverse",      rule_reverse     },
    { "leet",         rule_leet        },
    { "append_1",     rule_append_1    },
    { "append_bang",  rule_append_bang },
    { "append_123",   rule_append_123  },
};

const size_t rule_count = sizeof(rule_table) / sizeof(rule_table[0]);