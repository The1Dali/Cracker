#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include "hash.h"

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
    {
        sprintf(out + (i * 2), "%02x", bytes[i]);
    }
    out[len * 2] = '\0';
}

size_t hex_to_bytes(const char *hex, unsigned char *out)
{
    size_t count = 0;

    while (hex[0] != '\0' && hex[1] != '\0')
    {
        if (sscanf(hex, "%2hhx", &out[count]) != 1)
        {
            return 0;
        }
        hex   += 2;
        count += 1;
    }

    return count;
}

static void ntlm_hash(const unsigned char *input, size_t len, unsigned char *out)
{
    unsigned char utf16[510];
    size_t utf16_len = 0;

    for (size_t i = 0; i < len && utf16_len + 2 <= sizeof(utf16); i++)
    {
        utf16[utf16_len++] = input[i];
        utf16[utf16_len++] = 0x00;
    }

    MD4(utf16, utf16_len, out);
}

const HashDef hash_table[] =
{
     { "MD5",     16, (HashFn)MD5    },
     { "SHA-256", 32, (HashFn)SHA256 },
     { "SHA-512", 64, (HashFn)SHA512 },
     { "NTLM",   16, ntlm_hash      },
};

const size_t hash_table_size = sizeof(hash_table) / sizeof(hash_table[0]);

#define HASH_TABLE_SIZE hash_table_size

size_t hash_compute_raw(HashAlgo algo, const char *input, size_t len,
                        unsigned char *out_raw)
{
    if ((size_t)algo >= HASH_TABLE_SIZE)
    {
        return 0;
    }

    const HashDef *def = &hash_table[algo];

    def->fn((const unsigned char *)input, len, out_raw);

    return def->digest_len;
}

void hash_compute(HashAlgo algo, const char *input, size_t len, char *out_hex)
{
    unsigned char raw[64];

    size_t digest_len = hash_compute_raw(algo, input, len, raw);

    if (digest_len == 0)
    {
        out_hex[0] = '\0';
        return;
    }

    bytes_to_hex(raw, digest_len, out_hex);
}