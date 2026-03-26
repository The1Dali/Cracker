#ifndef CONFIG_H
#define CONFIG_H

typedef enum
{
    HASH_MD5    = 0,
    HASH_SHA256 = 1,
    HASH_SHA512 = 2,
    HASH_NTLM   = 3,
} HashAlgo;

typedef enum
{
    ATTACK_DICTIONARY  = 0,
    ATTACK_BRUTEFORCE  = 1,
} AttackMode;

#define CHARSET_LOWER   "abcdefghijklmnopqrstuvwxyz"
#define CHARSET_UPPER   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define CHARSET_DIGITS  "0123456789"
#define CHARSET_ALNUM   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define CHARSET_ALL     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

#define MAX_BF_LEN 16

typedef struct
{
    HashAlgo    algo;
    AttackMode  mode;
    char        hashfile[512];
    char        wordlist[512];
    char        charset[128];
    char        outfile[512];
    int         min_len;
    int         max_len;
    int         verbose;
} Config;

#endif