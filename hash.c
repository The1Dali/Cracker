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

void hash_compute(HashAlgo algo,const char *input, size_t len, char *out_hex)
{
    unsigned char raw[64];   

    switch (algo) 
    {
        case HASH_MD5:
            MD5((const unsigned char *)input, len, raw);
            bytes_to_hex(raw, 16, out_hex);  
            break;

        case HASH_SHA256:
            SHA256((const unsigned char *)input, len, raw);
            bytes_to_hex(raw, 32, out_hex);  
            break;

        case HASH_SHA512:
            SHA512((const unsigned char *)input, len, raw);
            bytes_to_hex(raw, 64, out_hex);   
            break;

        case HASH_NTLM:
            memset(out_hex, '0', 32);
            out_hex[32] = '\0';
            break;

        default:
            out_hex[0] = '\0';
            break;
    }
}