#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "hash.h"

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
    {
        sprintf(out + (i * 2), "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

static void ntlm_hash(const unsigned char *input, size_t len, unsigned char *out)
{
    (void)input;
    (void)len;
    memset(out, 0, 16);
}

static const HashDef hash_table[] =
{
    /* HASH_MD5    = 0 */ { "MD5",     16, (HashFn)MD5    },
    /* HASH_SHA256 = 1 */ { "SHA-256", 32, (HashFn)SHA256 },
    /* HASH_SHA512 = 2 */ { "SHA-512", 64, (HashFn)SHA512 },
    /* HASH_NTLM   = 3 */ { "NTLM",   16, ntlm_hash      },
};

#define HASH_TABLE_SIZE (sizeof(hash_table) / sizeof(hash_table[0]))

void hash_compute(HashAlgo algo, const char *input, size_t len, char *out_hex)
{
    if ((size_t)algo >= HASH_TABLE_SIZE)
    {
        out_hex[0] = '\0';
        return;
    }

    const HashDef    *def = &hash_table[algo];
    unsigned char     raw[64];

    def->fn((const unsigned char *)input, len, raw);

    bytes_to_hex(raw, def->digest_len, out_hex);
}